pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {ExoCapsuleStorage} from "../storage/ExoCapsuleStorage.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {WithdrawalContainer} from "../libraries/WithdrawalContainer.sol";

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";

contract ExoCapsule is
    Initializable,
    ExoCapsuleStorage,
    IExoCapsule
{
    using BeaconChainProofs for bytes32;
    using ValidatorContainer for bytes32[];
    using WithdrawalContainer for bytes32[];

    error InvalidValidatorContainer(bytes32 pubkey);
    error InvalidWithdrawalContainer(uint64 validatorIndex);
    error DoubleDepositedValidator(bytes32 pubkey);
    error GetBeaconBlockRootFailure(uint64 timestamp);
    error StaleValidatorContainer(bytes32 pubkey, uint64 timestamp);
    error UnregisteredOrWithdrawnValidatorContainer(bytes32 pubkey);
    error FullyWithdrawnValidatorContainer(bytes32 pubkey);
    error UnmatchedValidatorAndWithdrawal(bytes32 pubkey);
    error NotPartialWithdrawal(bytes32 pubkey);

    modifier onlyGateway() {
        require(msg.sender == address(gateway), "ExoCapsule: only client chain gateway could call this function");
        _;
    }

    constructor(address _gateway) {
        gateway = INativeRestakingController(_gateway);

        _disableInitializers();
    }

    function initialize(address _capsuleOwner) external initializer {
        require(_capsuleOwner != address(0), "ExoCapsule: capsule owner address can not be empty");
        capsuleOwner = _capsuleOwner;
    }

    function verifyDepositProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata proof
    ) external onlyGateway {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        Validator storage validator = _capsuleValidators[validatorPubkey];

        if (validator.status != VALIDATOR_STATUS.UNREGISTERED) {
            revert DoubleDepositedValidator(validatorPubkey);
        }

        if (_isStaleProof(validator, proof.beaconBlockTimestamp)) {
            revert StaleValidatorContainer(validatorPubkey, proof.beaconBlockTimestamp);
        }

        if (!validatorContainer.verifyValidatorContainerBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (!_isActivatedAtEpoch(validatorContainer, proof.beaconBlockTimestamp)) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (withdrawalCredentials != bytes32(capsuleWithdrawalCredentials())) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        _verifyValidatorContainer(validatorContainer, proof);

        validator.status = VALIDATOR_STATUS.REGISTERED;
        validator.validatorIndex = proof.validatorContainerRootIndex;
        validator.mostRecentBalanceUpdateTimestamp = proof.beaconBlockTimestamp;
        validator.restakedBalanceGwei = validatorContainer.getEffectiveBalance();

        _capsuleValidatorsByIndex[proof.validatorContainerRootIndex] = validatorPubkey;
    }

    function verifyPartialWithdrawalProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external onlyGateway {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        uint64 withdrawableEpoch = validatorContainer.getWithdrawableEpoch();

        bool partialWithdrawal = _timestampToEpoch(validatorProof.beaconBlockTimestamp) < withdrawableEpoch;

        if (!partialWithdrawal) {
            revert NotPartialWithdrawal(validatorPubkey);
        }

        if (validatorProof.beaconBlockTimestamp != withdrawalProof.beaconBlockTimestamp) {
            revert UnmatchedValidatorAndWithdrawal(validatorPubkey);
        }

        if (!validatorContainer.verifyValidatorContainerBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        _verifyValidatorContainer(validatorContainer, validatorProof);
        _verifyWithdrawalContainer(withdrawalContainer, withdrawalProof);
    }

    function verifyFullWithdrawalProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external onlyGateway {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        uint64 withdrawableEpoch = validatorContainer.getWithdrawableEpoch();

        Validator storage validator = _capsuleValidators[validatorPubkey];
        bool fullyWithdrawal = _timestampToEpoch(validatorProof.beaconBlockTimestamp) > withdrawableEpoch;

        if (!fullyWithdrawal) {
            revert NotPartialWithdrawal(validatorPubkey);
        }

        if (validatorProof.beaconBlockTimestamp != withdrawalProof.beaconBlockTimestamp) {
            revert UnmatchedValidatorAndWithdrawal(validatorPubkey);
        }

        if (!validatorContainer.verifyValidatorContainerBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        _verifyValidatorContainer(validatorContainer, validatorProof);
        _verifyWithdrawalContainer(withdrawalContainer, withdrawalProof);

        validator.status = VALIDATOR_STATUS.WITHDRAWN;
    }

    function withdraw(uint256 amount, address recipient) external onlyGateway {

    }

    function capsuleWithdrawalCredentials() public view returns (bytes memory) {
        /**
         * The withdrawal_credentials field must be such that:
         * withdrawal_credentials[:1] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
         * withdrawal_credentials[1:12] == b'\x00' * 11
         * withdrawal_credentials[12:] == eth1_withdrawal_address
         */
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }

    function getBeaconBlockRoot(uint64 timestamp) public returns (bytes32) {
        (bool success, bytes memory rootBytes) = BEACON_ROOTS_ADDRESS.call(abi.encodePacked(timestamp));
        if (!success) {
            revert GetBeaconBlockRootFailure(timestamp);
        }

        bytes32 beaconBlockRoot = abi.decode(rootBytes, (bytes32));
        return beaconBlockRoot;
    }

    function _verifyValidatorContainer(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof) internal {
        bytes32 beaconBlockRoot = getBeaconBlockRoot(proof.beaconBlockTimestamp);
        bytes32 validatorContainerRoot = validatorContainer.merklelizeValidatorContainer();
        bool valid = validatorContainerRoot.isValidValidatorContainerRoot(
            proof.validatorContainerRootProof,
            proof.validatorContainerRootIndex,
            beaconBlockRoot,
            proof.stateRoot,
            proof.stateRootProof
        );
        if (!valid) {
            revert InvalidValidatorContainer(validatorContainer.getPubkey());
        }
    }

    function _verifyWithdrawalContainer(bytes32[] calldata withdrawalContainer, WithdrawalContainerProof calldata proof) internal {
        bytes32 beaconBlockRoot = getBeaconBlockRoot(proof.beaconBlockTimestamp);
        bytes32 withdrawalContainerRoot = withdrawalContainer.merklelizeWithdrawalContainer();
        bool valid = withdrawalContainerRoot.isValidWithdrawalContainerRoot(
            proof.withdrawalContainerRootProof,
            proof.withdrawalContainerRootIndex,
            beaconBlockRoot,
            proof.executionPayloadRoot,
            proof.executionPayloadRootProof
        );
        if (!valid) {
            revert InvalidWithdrawalContainer(withdrawalContainer.getValidatorIndex());
        }
    }

    function _isActivatedAtEpoch(bytes32[] calldata validatorContainer, uint64 atTimestamp) internal pure returns (bool) {
        uint64 atEpoch = _timestampToEpoch(atTimestamp);
        uint64 activationEpoch = validatorContainer.getActivationEpoch();
        uint64 exitEpoch = validatorContainer.getExitEpoch();

        return (atEpoch >= activationEpoch && atEpoch < exitEpoch);
    }

    function _isStaleProof(Validator storage validator, uint64 proofTimestamp) internal view returns (bool) {
        if (proofTimestamp + VERIFY_BALANCE_UPDATE_WINDOW_SECONDS >= block.timestamp) {
            if (proofTimestamp > validator.mostRecentBalanceUpdateTimestamp) {
                return false;
            }
        }

        return true;
    }

    function _hasFullyWithdrawn(bytes32[] calldata validatorContainer) internal view returns (bool) {
        if (validatorContainer.getWithdrawableEpoch() <= _timestampToEpoch(uint64(block.timestamp))) {
            if (validatorContainer.getEffectiveBalance() == 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @dev Converts a timestamp to a beacon chain epoch by calculating the number of
     * seconds since genesis, and dividing by seconds per epoch.
     * reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md
     */
    function _timestampToEpoch(uint64 timestamp) internal pure returns (uint64) {
        require(timestamp >= BEACON_CHAIN_GENESIS_TIME, "timestamp should be greater than beacon chain genesis timestamp");
        return (timestamp - BEACON_CHAIN_GENESIS_TIME) / BeaconChainProofs.SECONDS_PER_EPOCH;
    }
}
