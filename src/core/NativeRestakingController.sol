pragma solidity ^0.8.19;

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {ExoCapsule} from "./ExoCapsule.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";

import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract NativeRestakingController is 
    PausableUpgradeable, 
    INativeRestakingController,
    BaseRestakingController
{
    using ValidatorContainer for bytes32[];

    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable whenNotPaused {
        require(msg.value == 32 ether, "NativeRestakingController: stake value must be exactly 32 ether");

        IExoCapsule capsule = ownerToCapsule[msg.sender];
        if (address(capsule) == address(0)) {
            capsule = IExoCapsule(createExoCapsule());
        }

        ETH_POS.deposit{value: 32 ether}(pubkey, capsule.capsuleWithdrawalCredentials(), signature, depositDataRoot);
        emit StakedWithCapsule(msg.sender, address(capsule));
    }

    function createExoCapsule() public whenNotPaused returns (address) {
        require(address(ownerToCapsule[msg.sender]) == address(0), "NativeRestakingController: message sender has already created the capsule");
    
        ExoCapsule capsule = new ExoCapsule(address(this));
        capsule.initialize(msg.sender);
        ownerToCapsule[msg.sender] = capsule;

        emit CapsuleCreated(msg.sender, address(capsule));

        return address(capsule);
    }

    function depositBeaconChainValidator(
        bytes32[] calldata validatorContainer, 
        IExoCapsule.ValidatorContainerProof calldata proof
    ) external whenNotPaused {
        IExoCapsule capsule = ownerToCapsule[msg.sender];
        if (address(capsule) == address(0)) {
            revert CapsuleNotExist();
        }

        capsule.verifyDepositProof(validatorContainer, proof);

        uint256 depositValue = uint256(validatorContainer.getEffectiveBalance()) * GWEI_TO_WEI;
        registeredRequests[outboundNonce + 1] = abi.encode(VIRTUAL_STAKED_ETH_ADDRESS, msg.sender, depositValue);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_DEPOSIT;

        bytes memory actionArgs = abi.encodePacked(
            bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)), 
            bytes32(bytes20(msg.sender)), 
            depositValue
        );
        
        _sendMsgToExocore(Action.REQUEST_DEPOSIT, actionArgs);
    }

    function processBeaconChainPartialWithdrawal(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        IExoCapsule.WithdrawalContainerProof calldata withdrawalProof
    ) external whenNotPaused {

    }

    function processBeaconChainFullWithdrawal(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        IExoCapsule.WithdrawalContainerProof calldata withdrawalProof
    ) external whenNotPaused {

    }
}