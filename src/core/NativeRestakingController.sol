pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";

import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";
import {ExoCapsule} from "./ExoCapsule.sol";

import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

abstract contract NativeRestakingController is
    PausableUpgradeable,
    INativeRestakingController,
    BaseRestakingController
{

    using ValidatorContainer for bytes32[];

    function stake(
        bytes calldata pubkey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external payable whenNotPaused {
        require(msg.value == 32 ether, "NativeRestakingController: stake value must be exactly 32 ether");

        IExoCapsule capsule = ownerToCapsule[msg.sender];
        if (address(capsule) == address(0)) {
            capsule = IExoCapsule(createExoCapsule());
        }

        ETH_POS.deposit{value: 32 ether}(pubkey, capsule.capsuleWithdrawalCredentials(), signature, depositDataRoot);
        emit StakedWithCapsule(msg.sender, address(capsule));
    }

    function createExoCapsule() public whenNotPaused returns (address) {
        require(
            address(ownerToCapsule[msg.sender]) == address(0),
            "NativeRestakingController: message sender has already created the capsule"
        );
        IExoCapsule capsule = IExoCapsule(
            Create2.deploy(
                0,
                bytes32(uint256(uint160(msg.sender))),
                // set the beacon address for beacon proxy
                abi.encodePacked(BEACON_PROXY_BYTECODE.getBytecode(), abi.encode(address(EXO_CAPSULE_BEACON), ""))
            )
        );
        capsule.initialize(address(this), msg.sender, BEACON_ORACLE_ADDRESS);
        ownerToCapsule[msg.sender] = capsule;

        emit CapsuleCreated(msg.sender, address(capsule));

        return address(capsule);
    }

    function withdrawBeforeRestaking() external whenNotPaused {
        IExoCapsule capsule = _getCapsule(msg.sender);
        capsule.withdrawBeforeRestaking();
    }

    function depositBeaconChainValidator(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata proof
    ) external payable whenNotPaused {
        IExoCapsule capsule = _getCapsule(msg.sender);
        // Before verifying deposit proof, we need to activate restaking and withdraw all potential ETH withdrawan to the exocapsule back to the owner. This amount won't be counted as staked balance
        capsule.activateRestaking();
        capsule.verifyDepositProof(validatorContainer, proof);

        uint256 depositValue = uint256(validatorContainer.getEffectiveBalance()) * GWEI_TO_WEI;
        _processRequest(VIRTUAL_STAKED_ETH_ADDRESS, msg.sender, depositValue, Action.REQUEST_DEPOSIT, "");
    }

    function processBeaconChainWithdrawal(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        IExoCapsule.WithdrawalContainerProof calldata withdrawalProof
    ) external payable whenNotPaused {
        IExoCapsule capsule = _getCapsule(msg.sender);
        (bool partialWithdrawal, uint256 withdrawalAmount) = capsule.verifyWithdrawalProof(
            validatorContainer,
            validatorProof,
            withdrawalContainer,
            withdrawalProof
        );
        if (!partialWithdrawal) {
            // request full withdraw
            _processRequest(
                VIRTUAL_STAKED_ETH_ADDRESS,
                msg.sender,
                withdrawalAmount,
                Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
                ""
            );
        }
    }
}
