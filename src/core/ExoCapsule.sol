pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {WithdrawalContainer} from "../libraries/WithdrawalContainer.sol";
import {ExoCapsuleStorage} from "../storage/ExoCapsuleStorage.sol";

import {IBeaconChainOracle} from "@beacon-oracle/contracts/src/IBeaconChainOracle.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";

contract ExoCapsule is Initializable, ExoCapsuleStorage, IExoCapsule {

    using BeaconChainProofs for bytes32;
    using ValidatorContainer for bytes32[];
    using WithdrawalContainer for bytes32[];

    event PrincipleBalanceUpdated(address, uint256);
    event WithdrawableBalanceUpdated(address, uint256);
    event WithdrawalSuccess(address, address, uint256);
    /// @notice Emitted when a partial withdrawal claim is successfully redeemed
    event PartialWithdrawalRedeemed(
        bytes32 pubkey, uint256 withdrawalTimestamp, address indexed recipient, uint64 partialWithdrawalAmountGwei
    );
    /// @notice Emitted when an ETH validator is prove to have fully withdrawn from the beacon chain
    event FullWithdrawalRedeemed(
        bytes32 pubkey, uint256 withdrawalTimestamp, address indexed recipient, uint64 withdrawalAmountGwei
    );
    /// @notice Emitted when capsuleOwner enables restaking
    event RestakingActivated(address indexed capsuleOwner);
    /// @notice Emitted when ETH is received via the `receive` fallback
    event NonBeaconChainETHReceived(uint256 amountReceived);
    /// @notice Emitted when ETH that was previously received via the `receive` fallback is withdrawn
    event NonBeaconChainETHWithdrawn(address indexed recipient, uint256 amountWithdrawn);

    error InvalidValidatorContainer(bytes32 pubkey);
    error InvalidWithdrawalContainer(uint64 validatorIndex);
    error InvalidHistoricalSummaries(uint64 validatorIndex);
    error DoubleDepositedValidator(bytes32 pubkey);
    error StaleValidatorContainer(bytes32 pubkey, uint256 timestamp);
    error WithdrawalAlreadyProven(bytes32 pubkey, uint256 timestamp);
    error UnregisteredValidator(bytes32 pubkey);
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

    receive() external payable {
        nonBeaconChainETHBalance += msg.value;
        emit NonBeaconChainETHReceived(msg.value);
    }

    function initialize(address gateway_, address capsuleOwner_, address beaconOracle_) external initializer {
        require(gateway_ != address(0), "ExoCapsule: gateway address can not be empty");
        require(capsuleOwner_ != address(0), "ExoCapsule: capsule owner address can not be empty");
        require(beaconOracle_ != address(0), "ExoCapsule: beacon chain oracle address should not be empty");

        gateway = INativeRestakingController(gateway_);
        beaconOracle = IBeaconChainOracle(beaconOracle_);
        capsuleOwner = capsuleOwner_;

        hasRestaked = true;
        emit RestakingActivated(capsuleOwner);
    }

    function verifyDepositProof(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof)
        external
        onlyGateway
    {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        Validator storage validator = _capsuleValidators[validatorPubkey];

        if (!validatorContainer.verifyValidatorContainerBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (validator.status != VALIDATOR_STATUS.UNREGISTERED) {
            revert DoubleDepositedValidator(validatorPubkey);
        }

        if (_isStaleProof(validator, proof.beaconBlockTimestamp)) {
            revert StaleValidatorContainer(validatorPubkey, proof.beaconBlockTimestamp);
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

    function verifyWithdrawalProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external onlyGateway returns (bool partialWithdrawal, uint256 withdrawalAmount) {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        uint64 withdrawableEpoch = validatorContainer.getWithdrawableEpoch();
        Validator storage validator = _capsuleValidators[validatorPubkey];
        partialWithdrawal = _timestampToEpoch(validatorProof.beaconBlockTimestamp) < withdrawableEpoch;

        if (!validatorContainer.verifyValidatorContainerBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (validatorProof.beaconBlockTimestamp != withdrawalProof.beaconBlockTimestamp) {
            revert UnmatchedValidatorAndWithdrawal(validatorPubkey);
        }

        if (validator.status == VALIDATOR_STATUS.UNREGISTERED) {
            revert UnregisteredOrWithdrawnValidatorContainer(validatorPubkey);
        }

        if (provenWithdrawal[validatorPubkey][withdrawalProof.beaconBlockTimestamp]) {
            revert WithdrawalAlreadyProven(validatorPubkey, withdrawalProof.beaconBlockTimestamp);
        }

        provenWithdrawal[validatorPubkey][withdrawalProof.beaconBlockTimestamp] = true;

        _verifyValidatorContainer(validatorContainer, validatorProof);
        _verifyWithdrawalContainer(withdrawalContainer, withdrawalProof);

        uint64 withdrawalAmountGwei = withdrawalContainer.getAmount();

        if (partialWithdrawal) {
            // Immediately send ETH without sending request to Exocore side
            emit PartialWithdrawalRedeemed(
                validatorPubkey, withdrawalProof.beaconBlockTimestamp, capsuleOwner, withdrawalAmountGwei
            );
            _sendETH(capsuleOwner, withdrawalAmountGwei * GWEI_TO_WEI);
        } else {
            // Full withdrawal
            validator.status = VALIDATOR_STATUS.WITHDRAWN;
            validator.restakedBalanceGwei = 0;
            // If over MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR = 32 * 1e9, then send remaining amount immediately
            emit FullWithdrawalRedeemed(
                validatorPubkey, withdrawalProof.beaconBlockTimestamp, capsuleOwner, withdrawalAmountGwei
            );
            if (withdrawalAmountGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
                withdrawalAmount = (withdrawalAmountGwei - MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) * GWEI_TO_WEI;
                _sendETH(capsuleOwner, withdrawalAmount);
            }
        }
    }

    function withdraw(uint256 amount, address payable recipient) external onlyGateway {
        require(
            amount <= withdrawableBalance, "ExoCapsule: withdrawal amount is larger than staker's withdrawable balance"
        );

        withdrawableBalance -= amount;
        _sendETH(recipient, amount);

        emit WithdrawalSuccess(capsuleOwner, recipient, amount);
    }

    /// @notice Called by the capsule owner to withdraw the nonBeaconChainETHBalance
    function withdrawNonBeaconChainETHBalance(address recipient, uint256 amountToWithdraw) external onlyGateway {
        require(
            amountToWithdraw <= nonBeaconChainETHBalance,
            "ExoCapsule.withdrawNonBeaconChainETHBalance: amountToWithdraw is greater than nonBeaconChainETHBalance"
        );
        nonBeaconChainETHBalance -= amountToWithdraw;
        _sendETH(recipient, amountToWithdraw);
        emit NonBeaconChainETHWithdrawn(recipient, amountToWithdraw);
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

    function getRegisteredValidatorByPubkey(bytes32 pubkey) public view returns (Validator memory) {
        Validator memory validator = _capsuleValidators[pubkey];
        if (validator.status == VALIDATOR_STATUS.UNREGISTERED) {
            revert UnregisteredValidator(pubkey);
        }

        return validator;
    }

    function getRegisteredValidatorByIndex(uint256 index) public view returns (Validator memory) {
        Validator memory validator = _capsuleValidators[_capsuleValidatorsByIndex[index]];
        if (validator.status == VALIDATOR_STATUS.UNREGISTERED) {
            revert UnregisteredValidator(_capsuleValidatorsByIndex[index]);
        }

        return validator;
    }

    function _processWithdrawalBeforeRestaking(address _capsuleOwner) internal {
        mostRecentWithdrawalTimestamp = block.timestamp;
        nonBeaconChainETHBalance = 0;
        _sendETH(_capsuleOwner, address(this).balance);
    }

    function _sendETH(address recipient, uint256 amountWei) internal {
        (bool sent,) = recipient.call{value: amountWei}("");
        if (!sent) {
            revert WithdrawalFailure(capsuleOwner, recipient, amountWei);
        }
    }

    function _verifyValidatorContainer(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof)
        internal
        view
    {
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

    function _verifyWithdrawalContainer(bytes32[] calldata withdrawalContainer, WithdrawalContainerProof calldata proof)
        internal
        view
    {
        bytes32 withdrawalContainerRoot = withdrawalContainer.merklelizeWithdrawalContainer();
        bool valid = withdrawalContainerRoot.isValidWithdrawalContainerRoot(
            proof.withdrawalContainerRootProof,
            proof.withdrawalIndex,
            proof.blockRoot,
            proof.executionPayloadRoot,
            proof.executionPayloadRootProof,
            proof.beaconBlockTimestamp
        );
        if (!valid) {
            revert InvalidWithdrawalContainer(withdrawalContainer.getValidatorIndex());
        }
        // Verify historical summaries
        bool validHistoricalSummaries = proof.stateRoot.isValidHistoricalSummaryRoot(
            proof.historicalSummaryBlockRootProof, proof.historicalSummaryIndex, proof.blockRoot, proof.blockRootIndex
        );
        if (!validHistoricalSummaries) {
            revert InvalidHistoricalSummaries(withdrawalContainer.getValidatorIndex());
        }
    }

    function _isActivatedAtEpoch(bytes32[] calldata validatorContainer, uint256 atTimestamp)
        internal
        pure
        returns (bool)
    {
        uint64 atEpoch = _timestampToEpoch(atTimestamp);
        uint64 activationEpoch = validatorContainer.getActivationEpoch();
        uint64 exitEpoch = validatorContainer.getExitEpoch();

        return (atEpoch >= activationEpoch && atEpoch < exitEpoch);
    }

    function _isStaleProof(Validator storage validator, uint256 proofTimestamp) internal view returns (bool) {
        return proofTimestamp + VERIFY_BALANCE_UPDATE_WINDOW_SECONDS < block.timestamp
            || proofTimestamp <= validator.mostRecentBalanceUpdateTimestamp;
    }

    function _hasFullyWithdrawn(bytes32[] calldata validatorContainer) internal view returns (bool) {
        return validatorContainer.getWithdrawableEpoch() <= _timestampToEpoch(block.timestamp)
            && validatorContainer.getEffectiveBalance() == 0;
    }

    /**
     * @dev Converts a timestamp to a beacon chain epoch by calculating the number of
     * seconds since genesis, and dividing by seconds per epoch.
     * reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md
     */
    function _timestampToEpoch(uint256 timestamp) internal pure returns (uint64) {
        require(
            timestamp >= BEACON_CHAIN_GENESIS_TIME, "timestamp should be greater than beacon chain genesis timestamp"
        );
        return uint64((timestamp - BEACON_CHAIN_GENESIS_TIME) / BeaconChainProofs.SECONDS_PER_EPOCH);
    }

}
