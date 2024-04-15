pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {ExoCapsuleStorage} from "../storage/ExoCapsuleStorage.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/security/PausableUpgradeable.sol";
import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {IClientChainGateway} from "../interfaces/IClientChainGateway.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {WithdrawalContainer} from "../libraries/WithdrawalContainer.sol";

contract ExoCapsule is 
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ExoCapsuleStorage,
    IExoCapsule
{
    using BeaconChainProofs for bytes;
    using ValidatorContainer for bytes32[];
    using WithdrawalContainer for bytes32[];

    IETHPOSDeposit public immutable ethPOS;

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
        require(msg.sender == address(gateway), "only client chain gateway could call this function");
        _;
    }

    constructor(address _ethPOS, address _gateway) {
        ethPOS = IETHPOSDeposit(_ethPOS);
        gateway = IClientChainGateway(_gateway);

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

        if (!validatorContainer.verifyBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (!_isActivatedAtEpoch(validatorContainer, proof.beaconBlockTimestamp)) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (withdrawalCredentials != _capsuleWithdrawalCredentials()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        _verifyValidatorContainer(validatorContainer, proof);

        validator.status = VALIDATOR_STATUS.REGISTERED;
        validator.validatorIndex = proof.validatorContainerRootIndex;
        validator.mostRecentBalanceUpdateTimestamp = proof.beaconBlockTimestamp;
        validator.restakedBalanceGwei = validatorContainer.getEffectiveBalance();

        _capsuleValidatorsByIndex[proof.ValidatorContainerRootIndex] = validatorPubkey;
    }

    function updateStakeBalance(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata proof
    ) external onlyGateway {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        Validator storage validator = _capsuleValidators[validatorPubkey];

        if (Validator.status != VALIDATOR_STATUS.REGISTERED) {
            revert UnregisteredOrWithdrawnValidatorContainer(validatorPubkey);
        }

        if (_isStaleProof(validator, proof.beaconBlockTimestamp)) {
            revert StaleValidatorContainer(validatorPubkey, proof.beaconBlockTimestamp);
        }

        if (!validatorContainer.verifyBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (_hasFullyWithdrawn(validatorContainer)) {
            revert FullyWithdrawnValidatorContainer(validatorPubkey);
        }

        _verifyValidatorContainer(validatorContainer, proof);

        validator.mostRecentBalanceUpdateTimestamp = proof.beaconBlockTimestamp;
        validator.restakedBalanceGwei = validatorContainer.getEffectiveBalance();
    }

    function partiallyWithdraw(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external onlyGateway {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        uint64 withdrawableEpoch = validatorContainer.getWithdrawableEpoch();

        Validator storage validator = _capsuleValidators[validatorPubkey];
        bool partialWithdrawal = _timestampToEpoch(validatorProof.beaconBlockTimestamp) < withdrawableEpoch;

        if (!partialWithdrawal) {
            revert NotPartialWithdrawal(validatorPubkey);
        }

        if (validatorProof.beaconBlockTimestamp != withdrawalProof.beaconBlockTimestamp) {
            revert UnmatchedValidatorAndWithdrawal(validatorPubkey);
        }

        if (!validatorContainer.verifyBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        _verifyValidatorContainer(validatorContainer, validatorProof);
        _verifyWithdrawalContainer(withdrawalContainer, withdrawalProof);
    }

    function fullyWithdraw(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external onlyGateway {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        uint64 withdrawableEpoch = validatorContainer.getWithdrawableEpoch();

        Validator storage validator = _capsuleValidators[validatorPubkey];
        bool fullyWithdrawal = _timestampToEpoch(validatorProof.beaconBlockTimestamp) > withdrawableEpoch;

        if (!fullyWithdrawal) {
            revert NotPartialWithdrawal(validatorPubkey);
        }

        if (validatorProof.beaconBlockTimestamp != withdrawalProof.beaconBlockTimestamp) {
            revert UnmatchedValidatorAndWithdrawal(validatorPubkey);
        }

        if (!validatorContainer.verifyBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        _verifyValidatorContainer(validatorContainer, validatorProof);
        _verifyWithdrawalContainer(withdrawalContainer, withdrawalProof);

        validator.status = VALIDATOR_STATUS.EXITED;
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

    function _verifyValidatorContainer(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof) internal {
        bytes32 beaconBlockRoot = getBeaconBlockRoot(proof.beaconBlockTimestamp);
        bytes32 validatorContainerRoot = validatorContainer.merklelize();
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
        bytes32 withdrawalContainerRoot = withdrawalContainer.merklelize();
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

    function _isActivatedAtEpoch(bytes32[] calldata validatorContainer, uint64 atTimestamp) internal view returns (bool) {
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
        if (validatorContainer.getWithdrawableEpoch() <= _timestampToEpoch(block.timestamp)) {
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
    function _timestampToEpoch(uint64 timestamp) internal view returns (uint64) {
        require(timestamp >= BEACON_CHAIN_GENESIS_TIME, "timestamp should be greater than beacon chain genesis timestamp");
        return (timestamp - BEACON_CHAIN_GENESIS_TIME) / BeaconChainProofs.SECONDS_PER_EPOCH;
    }
}
