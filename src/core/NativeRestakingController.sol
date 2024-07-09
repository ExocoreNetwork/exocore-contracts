pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";

import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";
import {ExoCapsule} from "./ExoCapsule.sol";

import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

abstract contract NativeRestakingController is
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    INativeRestakingController,
    BaseRestakingController
{

    using ValidatorContainer for bytes32[];

    modifier nativeRestakingEnabled() {
        require(
            isWhitelistedToken[VIRTUAL_STAKED_ETH_ADDRESS], "NativeRestakingController: native restaking is not enabled"
        );
        _;
    }

    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        whenNotPaused
        nonReentrant
        nativeRestakingEnabled
    {
        require(msg.value == 32 ether, "NativeRestakingController: stake value must be exactly 32 ether");

        IExoCapsule capsule = ownerToCapsule[msg.sender];
        if (address(capsule) == address(0)) {
            capsule = IExoCapsule(createExoCapsule());
        }

        ETH_POS.deposit{value: 32 ether}(pubkey, capsule.capsuleWithdrawalCredentials(), signature, depositDataRoot);
        emit StakedWithCapsule(msg.sender, address(capsule));
    }

    // The bytecode returned by `BEACON_PROXY_BYTECODE` and `EXO_CAPSULE_BEACON` address are actually fixed size of byte
    // array, so it would not cause collision for encodePacked
    // slither-disable-next-line encode-packed-collision
    function createExoCapsule() public whenNotPaused nativeRestakingEnabled returns (address) {
        require(
            address(ownerToCapsule[msg.sender]) == address(0),
            "NativeRestakingController: message sender has already created the capsule"
        );
        ExoCapsule capsule = ExoCapsule(
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

    function depositBeaconChainValidator(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata proof
    ) external payable whenNotPaused nonReentrant nativeRestakingEnabled {
        IExoCapsule capsule = _getCapsule(msg.sender);
        capsule.verifyDepositProof(validatorContainer, proof);

        uint256 depositValue = uint256(validatorContainer.getEffectiveBalance()) * GWEI_TO_WEI;

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)), bytes32(bytes20(msg.sender)), depositValue);
        bytes memory encodedRequest = abi.encode(VIRTUAL_STAKED_ETH_ADDRESS, msg.sender, depositValue);
        _processRequest(Action.REQUEST_DEPOSIT, actionArgs, encodedRequest);
    }

    function processBeaconChainPartialWithdrawal(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        IExoCapsule.WithdrawalContainerProof calldata withdrawalProof
    ) external payable whenNotPaused nonReentrant nativeRestakingEnabled {}

    function processBeaconChainFullWithdrawal(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        IExoCapsule.WithdrawalContainerProof calldata withdrawalProof
    ) external payable whenNotPaused nonReentrant nativeRestakingEnabled {}

}
