// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";

import {Errors} from "../libraries/Errors.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/// @title NativeRestakingController
/// @author ExocoreNetwork
/// @notice This is the implementation of INativeRestakingController. It allows Ethereum validators
/// to stake, deposit and withdraw from the Ethereum beacon chain.
/// @dev This contract is abstract because it does not call the base constructor.
abstract contract NativeRestakingController is
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    INativeRestakingController,
    BaseRestakingController
{

    using ValidatorContainer for bytes32[];

    /// @dev Ensures that native restaking is enabled for this contract.
    modifier nativeRestakingEnabled() {
        if (!isWhitelistedToken[VIRTUAL_STAKED_ETH_ADDRESS]) {
            revert Errors.NativeRestakingControllerNotWhitelisted();
        }
        _;
    }

    /// @notice Stakes 32 ETH on behalf of the validators in the Ethereum beacon chain, and
    /// points the withdrawal credentials to the capsule contract, creating it if necessary.
    /// @param pubkey The validator's BLS12-381 public key.
    /// @param signature Value signed by the @param pubkey.
    /// @param depositDataRoot The SHA-256 hash of the SSZ-encoded DepositData object.
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        if (msg.value != 32 ether) {
            revert Errors.NativeRestakingControllerInvalidStakeValue();
        }

        IExoCapsule capsule = ownerToCapsule[msg.sender];
        if (address(capsule) == address(0)) {
            capsule = IExoCapsule(createExoCapsule());
        }

        ETH_POS.deposit{value: 32 ether}(pubkey, capsule.capsuleWithdrawalCredentials(), signature, depositDataRoot);
        emit StakedWithCapsule(msg.sender, address(capsule));
    }

    /// @notice Creates a new ExoCapsule contract for the message sender.
    /// @return The address of the newly created ExoCapsule contract.
    // The bytecode returned by `BEACON_PROXY_BYTECODE` and `EXO_CAPSULE_BEACON` address are actually fixed size of byte
    // array, so it would not cause collision for encodePacked
    // slither-disable-next-line encode-packed-collision
    function createExoCapsule() public whenNotPaused nativeRestakingEnabled returns (address) {
        if (address(ownerToCapsule[msg.sender]) != address(0)) {
            revert Errors.NativeRestakingControllerCapsuleAlreadyCreated();
        }
        IExoCapsule capsule = IExoCapsule(
            Create2.deploy(
                0,
                bytes32(uint256(uint160(msg.sender))),
                // set the beacon address for beacon proxy
                abi.encodePacked(BEACON_PROXY_BYTECODE.getBytecode(), abi.encode(address(EXO_CAPSULE_BEACON), ""))
            )
        );

        // we follow check-effects-interactions pattern to write state before external call
        ownerToCapsule[msg.sender] = capsule;
        capsule.initialize(address(this), msg.sender, BEACON_ORACLE_ADDRESS);

        emit CapsuleCreated(msg.sender, address(capsule));

        return address(capsule);
    }

    /// @notice Verifies a deposit proof from the beacon chain and forwards the information to Exocore.
    /// @param validatorContainer The validator container which made the deposit.
    /// @param proof The proof of the validator container.
    function depositBeaconChainValidator(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata proof
    ) external payable whenNotPaused nonReentrant nativeRestakingEnabled {
        IExoCapsule capsule = _getCapsule(msg.sender);
        uint256 depositValue = capsule.verifyDepositProof(validatorContainer, proof);

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)), bytes32(bytes20(msg.sender)), depositValue);
        bytes memory encodedRequest = abi.encode(VIRTUAL_STAKED_ETH_ADDRESS, msg.sender, depositValue);
        _processRequest(Action.REQUEST_DEPOSIT, actionArgs, encodedRequest);
    }

    /// @notice Verifies a withdrawal proof from the beacon chain and forwards the information to Exocore.
    /// @param validatorContainer The validator container which made the withdrawal.
    /// @param validatorProof The proof of the validator container.
    /// @param withdrawalContainer The withdrawal container.
    /// @param withdrawalProof The proof of the withdrawal.
    function processBeaconChainWithdrawal(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        BeaconChainProofs.WithdrawalProof calldata withdrawalProof
    ) external payable whenNotPaused nonReentrant nativeRestakingEnabled {
        IExoCapsule capsule = _getCapsule(msg.sender);
        (bool partialWithdrawal, uint256 withdrawalAmount) =
            capsule.verifyWithdrawalProof(validatorContainer, validatorProof, withdrawalContainer, withdrawalProof);
        if (!partialWithdrawal) {
            // request full withdraw
            bytes memory actionArgs = abi.encodePacked(
                bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)), bytes32(bytes20(msg.sender)), withdrawalAmount
            );
            bytes memory encodedRequest = abi.encode(VIRTUAL_STAKED_ETH_ADDRESS, msg.sender, withdrawalAmount);

            _processRequest(Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE, actionArgs, encodedRequest);
        }
    }

}
