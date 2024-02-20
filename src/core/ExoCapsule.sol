pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {ExoCapsuleStorage} from "../storage/ExoCapsuleStorage.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/security/PausableUpgradeable.sol";
import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";

contract ExoCapsule is 
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ExoCapsuleStorage,
    IExoCapsule
{
    using BeaconChainProofs for bytes;

    IETHPOSDeposit public immutable ethPOS;

    constructor(IETHPOSDeposit _ethPOS) {
        ethPOS = _ethPOS;

        _disableInitializers();
    }

    function initialize(
        address payable _ExocoreValidatorSetAddress
    ) 
        external 
        initializer 
    {
        require(_ExocoreValidatorSetAddress != address(0), "invalid empty exocore validator set address");
        exocoreValidatorSetAddress = _ExocoreValidatorSetAddress;

        _transferOwnership(exocoreValidatorSetAddress);
        __Pausable_init();
    }

    function pause() external {
        require(msg.sender == exocoreValidatorSetAddress, "only Exocore validator set aggregated address could call this");
        _pause();
    }

    function unpause() external {
        require(msg.sender == exocoreValidatorSetAddress, "only Exocore validator set aggregated address could call this");
        _unpause();
    }

    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable {
        
    }

    function deposit(
        uint64 beaconBlockTimestamp,
        bytes32 beaconStateRoot,
        bytes[] calldata beaconStateRootProof,
        bytes32[][] calldata validatorFields,
        uint40[] calldata validatorProofIndices,
        bytes[] calldata validatorFieldsProof
    ) external {

    }

    function updateStakeBalance(
        uint64 beaconBlockTimestamp,
        bytes32 beaconStateRoot,
        bytes[] calldata beaconStateRootProof,
        bytes32[][] calldata validatorFields,
        uint40[] calldata validatorProofIndices,
        bytes[] calldata validatorFieldsProof
    ) external {

    }

    function withdraw(
        uint64 beaconBlockTimestamp,
        bytes32 beaconStateRoot,
        bytes[] calldata beaconStateRootProof,
        bytes32[][] calldata withdrawalFields,
        uint40[] calldata withdrawalProofIndices,
        bytes[] calldata withdrawalFieldsProof
    ) external {

    }
}
