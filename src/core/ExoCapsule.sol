pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {ExoCapsuleStorage} from "../storage/ExoCapsuleStorage.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {WithdrawalContainer} from "../libraries/WithdrawalContainer.sol";

import {IBeaconChainOracle} from "@beacon-oracle/contracts/src/IBeaconChainOracle.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";

contract ExoCapsule is
    Initializable,
    ExoCapsuleStorage,
    IExoCapsule
{
    using BeaconChainProofs for bytes32;
    using ValidatorContainer for bytes32[];
    using WithdrawalContainer for bytes32[];

    event PrincipleBalanceUpdated(address, uint256);
    event WithdrawableBalanceUpdated(address, uint256);
    event WithdrawalSuccess(address, address, uint256);

    error InvalidValidatorContainer(bytes32 pubkey);
    error InvalidWithdrawalContainer(uint64 validatorIndex);
    error DoubleDepositedValidator(bytes32 pubkey);
    error StaleValidatorContainer(bytes32 pubkey, uint256 timestamp);
    error UnregisteredOrWithdrawnValidatorContainer(bytes32 pubkey);
    error FullyWithdrawnValidatorContainer(bytes32 pubkey);
    error UnmatchedValidatorAndWithdrawal(bytes32 pubkey);
    error NotPartialWithdrawal(bytes32 pubkey);
    error BeaconChainOracleNotUpdatedAtTime(address oracle, uint256 timestamp);
    error WithdrawalFailure(address withdrawer, address recipient, uint256 amount);
    error WithdrawalCredentialsNotMatch();
    error InactiveValidatorContainer(bytes32 pubkey);
    error InvalidGateway(address, address);

    modifier onlyGateway() {
        if (msg.sender != address(gateway)) {
            revert InvalidGateway(address(gateway), msg.sender);
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address gateway_, address capsuleOwner_, address beaconOracle_) external initializer {
        require(gateway_ != address(0), "ExoCapsuleStorage: gateway address can not be empty");
        require(capsuleOwner_ != address(0), "ExoCapsule: capsule owner address can not be empty");
        require(beaconOracle_ != address(0), "ExoCapsuleStorage: beacon chain oracle address should not be empty");

        gateway = INativeRestakingController(gateway_);
        beaconOracle = IBeaconChainOracle(beaconOracle_);
        capsuleOwner = capsuleOwner_;
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
            revert InactiveValidatorContainer(validatorPubkey);
        }

        if (withdrawalCredentials != bytes32(capsuleWithdrawalCredentials())) {
            revert WithdrawalCredentialsNotMatch();
        }

        _verifyValidatorContainer(validatorContainer, proof);

        validator.status = VALIDATOR_STATUS.REGISTERED;
        validator.validatorIndex = proof.validatorIndex;
        validator.mostRecentBalanceUpdateTimestamp = proof.beaconBlockTimestamp;
        validator.restakedBalanceGwei = validatorContainer.getEffectiveBalance();

        _capsuleValidatorsByIndex[proof.validatorIndex] = validatorPubkey;
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
        require(
            amount <= withdrawableBalance,
            "ExoCapsule: withdrawal amount is larger than staker's withdrawable balance"
        );

        withdrawableBalance -= amount;
        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) {
            revert WithdrawalFailure(capsuleOwner, recipient, amount);
        }

        emit WithdrawalSuccess(capsuleOwner, recipient, amount);
    }

    function updatePrincipleBalance(uint256 lastlyUpdatedPrincipleBalance) external onlyGateway {
        principleBalance = lastlyUpdatedPrincipleBalance;

        emit PrincipleBalanceUpdated(capsuleOwner, lastlyUpdatedPrincipleBalance);
    }

    function updateWithdrawableBalance(uint256 unlockPrincipleAmount) external onlyGateway {
        withdrawableBalance += unlockPrincipleAmount;

        emit WithdrawableBalanceUpdated(capsuleOwner, unlockPrincipleAmount);
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

    function getBeaconBlockRoot(uint256 timestamp) public view returns (bytes32) {
        bytes32 root = beaconOracle.timestampToBlockRoot(timestamp);
        if (root == bytes32(0)) {
            revert BeaconChainOracleNotUpdatedAtTime(address(beaconOracle), timestamp);
        }

        return root;
    }

    function _verifyValidatorContainer(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof) internal view {
        bytes32 beaconBlockRoot = getBeaconBlockRoot(proof.beaconBlockTimestamp);
        bytes32 validatorContainerRoot = validatorContainer.merklelizeValidatorContainer();
        bool valid = validatorContainerRoot.isValidValidatorContainerRoot(
            proof.validatorContainerRootProof,
            proof.validatorIndex,
            beaconBlockRoot,
            proof.stateRoot,
            proof.stateRootProof
        );
        if (!valid) {
            revert InvalidValidatorContainer(validatorContainer.getPubkey());
        }
    }

    function _verifyWithdrawalContainer(bytes32[] calldata withdrawalContainer, WithdrawalContainerProof calldata proof) internal view {
        bytes32 beaconBlockRoot = getBeaconBlockRoot(proof.beaconBlockTimestamp);
        bytes32 withdrawalContainerRoot = withdrawalContainer.merklelizeWithdrawalContainer();
        bool valid = withdrawalContainerRoot.isValidWithdrawalContainerRoot(
            proof.withdrawalContainerRootProof,
            proof.withdrawalIndex,
            beaconBlockRoot,
            proof.executionPayloadRoot,
            proof.executionPayloadRootProof
        );
        if (!valid) {
            revert InvalidWithdrawalContainer(withdrawalContainer.getValidatorIndex());
        }
    }

    function _isActivatedAtEpoch(bytes32[] calldata validatorContainer, uint256 atTimestamp) internal pure returns (bool) {
        uint64 atEpoch = _timestampToEpoch(atTimestamp);
        uint64 activationEpoch = validatorContainer.getActivationEpoch();
        uint64 exitEpoch = validatorContainer.getExitEpoch();

        return (atEpoch >= activationEpoch && atEpoch < exitEpoch);
    }

    function _isStaleProof(Validator storage validator, uint256 proofTimestamp) internal view returns (bool) {
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
    function _timestampToEpoch(uint256 timestamp) internal pure returns (uint64) {
        require(timestamp >= BEACON_CHAIN_GENESIS_TIME, "timestamp should be greater than beacon chain genesis timestamp");
        return uint64((timestamp - BEACON_CHAIN_GENESIS_TIME) / BeaconChainProofs.SECONDS_PER_EPOCH);
    }
}
