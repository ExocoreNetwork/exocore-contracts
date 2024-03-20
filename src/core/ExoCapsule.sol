pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {ExoCapsuleStorage} from "../storage/ExoCapsuleStorage.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/security/PausableUpgradeable.sol";
import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";

contract ExoCapsule is 
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ExoCapsuleStorage,
    IExoCapsule
{
    using BeaconChainProofs for bytes;
    using ValidatorContainer for bytes32[];

    IETHPOSDeposit public immutable ethPOS;

    error InvalidValidatorContainer(bytes32 pubkey);
    error DoubleDepositedValidator(bytes32 pubkey);
    error GetBeaconBlockRootFailure(uint64 timestamp);
    error StaleValidatorContainer(bytes32 pubkey, uint64 timestamp);

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
        require(msg.value == 32 ether, "stake value must be exactly 32 ether");
        ethPOS.deposit{value: 32 ether}(pubkey, _capsuleWithdrawalCredentials(), signature, depositDataRoot);
        emit StakedWithThisCapsule();
    }

    function deposit(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata proof
    ) external {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        ValidatorInfo storage validator = validatorStore[validatorPubkey];

        if (validator.status != VALIDATOR_STATUS.UNREGISTERED) {
            revert DoubleDepositedValidator(validatorPubkey);
        }

        if (_isStaleProof(validator, proof.beaconBlockTimestamp)) {
            revert StaleValidatorContainer(validatorPubkey, proof.beaconBlockTimestamp);
        }

        if (!validatorContainer.verifyBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (!_isActivatedAtEpoch(validatorContainer, proof.beaconBlockTimestamp)) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (withdrawalCredentials != _capsuleWithdrawalCredentials()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        bytes32 beaconBlockRoot = getBeaconBlockRoot(proof.beaconBlockTimestamp);
        bytes32 validatorContainerRoot = validatorContainer.merklelize();
        bool valid = validatorContainerRoot.verifyValidatorContainerRoot(
            proof.validatorContainerRootProof,
            proof.validatorContainerRootIndex,
            beaconBlockRoot,
            proof.stateRoot,
            proof.stateRootProof
        );
        if (!valid) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        validator.status = VALIDATOR_STATUS.REGISTERED;
        validator.validatorIndex = proof.validatorContainerRootIndex;
        validator.mostRecentBalanceUpdateTimestamp = proof.beaconBlockTimestamp;
        validator.restakedBalanceGwei = validatorContainer.getEffectiveBalance();
    }

    function updateStakeBalance(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata proof
    ) external {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        ValidatorInfo storage validator = validatorStore[validatorPubkey];

        if (validatorInfo.status != VALIDATOR_STATUS.REGISTERED) {
            revert DoubleDepositedValidator(validatorPubkey);
        }

        if (_isStaleProof(validator, proof.beaconBlockTimestamp)) {
            revert StaleValidatorContainer(validatorPubkey, proof.beaconBlockTimestamp);
        }

        if (!validatorContainer.verifyBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (proof.beaconBlockTimestamp <= validatorInfo.mostRecentBalanceUpdateTimestamp) {
            revert 
        }
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

    function _capsuleWithdrawalCredentials() internal view returns (bytes memory) {
        /**
         * The withdrawal_credentials field must be such that:
         * withdrawal_credentials[:1] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
         * withdrawal_credentials[1:12] == b'\x00' * 11
         * withdrawal_credentials[12:] == eth1_withdrawal_address
         */
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }

    function getBeaconBlockRoot(uint64 timestamp) public view returns (bytes32) {
        (bool success, bytes memory rootBytes) = BEACON_ROOTS_ADDRESS.call{value: bytes32(bytes8(timestamp))}
        if (!success) {
            revert GetBeaconBlockRootFailure(timestamp);
        }

        bytes32 beaconBlockRoot = abi.decode(rootBytes, (bytes32));
        return beaconBlockRoot;
    }

    function _isActivatedAtEpoch(bytes32[] calldata validatorContainer, uint64 atTimestamp) internal view returns (bool) {
        uint64 atEpoch = _timestampToEpoch(atTimestamp);
        uint64 activationEpoch = validatorContainer.getActivationEpoch();
        uint64 exitEpoch = validatorContainer.getExitEpoch();
        
        return (atEpoch >= activationEpoch && atEpoch < exitEpoch);
    }

    function _isStaleProof(ValidatorInfo storage validator, uint64 proofTimestamp) internal view returns (bool) {
        if (proofTimestamp + VERIFY_BALANCE_UPDATE_WINDOW_SECONDS >= block.timestamp) {
            if (proofTimestamp > validator.mostRecentBalanceUpdateTimestamp) {
                return false;
            }
        }
    }

    function _isMoreRecent(uint64 timestamp) internal view returns (bool) {
        return timestamp > 
    }

    /**
     * @dev Converts a timestamp to a beacon chain epoch by calculating the number of
     * seconds since genesis, and dividing by seconds per epoch.
     * reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md
     */
    function _timestampToEpoch(uint64 timestamp) internal view returns (uint64) {
        require(timestamp >= BEACON_CHAIN_GENESIS_TIME, "timestamp should be greater than beacon chain genesis timestamp");
        return (timestamp - BEACON_CHAIN_GENESIS_TIME) / BeaconChainProofs.SECONDS_PER_EPOCH;
    }
}
