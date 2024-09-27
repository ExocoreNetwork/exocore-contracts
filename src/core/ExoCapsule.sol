// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {Endian} from "../libraries/Endian.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import {WithdrawalContainer} from "../libraries/WithdrawalContainer.sol";
import {ExoCapsuleStorage} from "../storage/ExoCapsuleStorage.sol";

import {IBeaconChainOracle} from "@beacon-oracle/contracts/src/IBeaconChainOracle.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/// @title ExoCapsule
/// @author ExocoreNetwork
/// @notice The ExoCapsule contract is used to stake, deposit and withdraw from the Ethereum beacon chain.
contract ExoCapsule is ReentrancyGuardUpgradeable, ExoCapsuleStorage, IExoCapsule {

    using BeaconChainProofs for bytes32;
    using Endian for bytes32;
    using ValidatorContainer for bytes32[];
    using WithdrawalContainer for bytes32[];

    /// @notice Emitted when the withdrawable balance of the capsule is updated.
    /// @param owner The address of the capsule owner.
    /// @param additionalAmount The amount added to the withdrawable balance.
    event WithdrawableBalanceUpdated(address owner, uint256 additionalAmount);

    /// @notice Emitted when a withdrawal is successfully completed.
    /// @param owner The address of the capsule owner.
    /// @param recipient The address of the recipient of the withdrawal.
    /// @param amount The amount withdrawn.
    event WithdrawalSuccess(address owner, address recipient, uint256 amount);

    /// @notice Emitted when a partial withdrawal claim is successfully redeemed
    /// @param pubkey The validator's BLS12-381 public key.
    /// @param withdrawalEpoch The epoch at which the withdrawal was made.
    /// @param recipient The address of the recipient of the withdrawal.
    /// @param partialWithdrawalAmountGwei The amount of the partial withdrawal in Gwei.
    event PartialWithdrawalRedeemed(
        bytes32 pubkey, uint256 withdrawalEpoch, address indexed recipient, uint64 partialWithdrawalAmountGwei
    );

    /// @notice Emitted when an ETH validator is prove to have fully withdrawn from the beacon chain
    /// @param pubkey  The validator's BLS12-381 public key.
    /// @param withdrawalEpoch The epoch at which the withdrawal was made.
    /// @param recipient The address of the recipient of the withdrawal.
    /// @param withdrawalAmountGwei The amount of the withdrawal in Gwei.
    event FullWithdrawalRedeemed(
        bytes32 pubkey, uint64 withdrawalEpoch, address indexed recipient, uint64 withdrawalAmountGwei
    );

    /// @notice Emitted when capsuleOwner enables restaking
    /// @param capsuleOwner The address of the capsule owner.
    event RestakingActivated(address indexed capsuleOwner);

    /// @notice Emitted when ETH is received via the `receive` fallback
    /// @param amountReceived The amount of ETH received
    event NonBeaconChainETHReceived(uint256 amountReceived);

    /// @notice Emitted when ETH that was previously received via the `receive` fallback is withdrawn
    /// @param recipient The address of the recipient of the withdrawal
    /// @param amountWithdrawn The amount of ETH withdrawn
    event NonBeaconChainETHWithdrawn(address indexed recipient, uint256 amountWithdrawn);

    /// @dev Thrown when the validator container is invalid.
    /// @param pubkey The validator's BLS12-381 public key.
    error InvalidValidatorContainer(bytes32 pubkey);

    /// @dev Thrown when the withdrawal container is invalid.
    /// @param validatorIndex The validator index.
    error InvalidWithdrawalContainer(uint64 validatorIndex);

    /// @dev Thrown when a validator is double deposited.
    /// @param pubkey The validator's BLS12-381 public key.
    error DoubleDepositedValidator(bytes32 pubkey);

    /// @dev Thrown when a validator container is stale.
    /// @param pubkey The validator's BLS12-381 public key.
    /// @param timestamp The timestamp of the validator proof.
    error StaleValidatorContainer(bytes32 pubkey, uint256 timestamp);

    /// @dev Thrown when a withdrawal has already been proven.
    /// @param pubkey The validator's BLS12-381 public key.
    /// @param withdrawalIndex The index of the withdrawal.
    error WithdrawalAlreadyProven(bytes32 pubkey, uint256 withdrawalIndex);

    /// @dev Thrown when a validator container is unregistered.
    /// @param pubkey The validator's BLS12-381 public key.
    error UnregisteredValidator(bytes32 pubkey);

    /// @dev Thrown when a validator container is unregistered or withdrawn.
    /// @param pubkey The validator's BLS12-381 public key.
    error UnregisteredOrWithdrawnValidatorContainer(bytes32 pubkey);

    /// @dev Thrown when the validator and withdrawal state roots do not match.
    /// @param validatorStateRoot The state root of the validator container.
    /// @param withdrawalStateRoot The state root of the withdrawal container.
    error UnmatchedValidatorAndWithdrawal(bytes32 validatorStateRoot, bytes32 withdrawalStateRoot);

    /// @dev Thrown when the beacon chain oracle does not have the root at the given timestamp.
    /// @param oracle The address of the beacon chain oracle.
    /// @param timestamp The timestamp for which the root is not available.
    error BeaconChainOracleNotUpdatedAtTime(address oracle, uint256 timestamp);

    /// @dev Thrown when sending ETH to @param recipient fails.
    /// @param withdrawer The address of the withdrawer.
    /// @param recipient The address of the recipient.
    /// @param amount The amount of ETH withdrawn.
    error WithdrawalFailure(address withdrawer, address recipient, uint256 amount);

    /// @dev Thrown when the validator's withdrawal credentials differ from the expected credentials.
    error WithdrawalCredentialsNotMatch();

    /// @dev Thrown when the validator container is inactive.
    /// @param pubkey The validator's BLS12-381 public key.
    error InactiveValidatorContainer(bytes32 pubkey);

    /// @dev Thrown when the caller of a message is not the gateway
    /// @param gateway The address of the gateway.
    /// @param caller The address of the caller.
    error InvalidCaller(address gateway, address caller);

    /// @dev Ensures that the caller is the gateway.
    modifier onlyGateway() {
        if (msg.sender != address(gateway)) {
            revert InvalidCaller(address(gateway), msg.sender);
        }
        _;
    }

    /// @notice Constructor to create the ExoCapsule contract.
    constructor() {
        _disableInitializers();
    }

    /// @notice Fallback function to receive ETH from outside the beacon chain.
    receive() external payable {
        nonBeaconChainETHBalance += msg.value;
        emit NonBeaconChainETHReceived(msg.value);
    }

    /// @inheritdoc IExoCapsule
    function initialize(address gateway_, address payable capsuleOwner_, address beaconOracle_) external initializer {
        require(gateway_ != address(0), "ExoCapsule: gateway address can not be empty");
        require(capsuleOwner_ != address(0), "ExoCapsule: capsule owner address can not be empty");
        require(beaconOracle_ != address(0), "ExoCapsule: beacon chain oracle address should not be empty");

        gateway = INativeRestakingController(gateway_);
        beaconOracle = IBeaconChainOracle(beaconOracle_);
        capsuleOwner = capsuleOwner_;

        __ReentrancyGuard_init_unchained();

        emit RestakingActivated(capsuleOwner);
    }

    /// @inheritdoc IExoCapsule
    function verifyDepositProof(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata proof
    ) external onlyGateway returns (uint256 depositAmount) {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        bytes32 withdrawalCredentials = validatorContainer.getWithdrawalCredentials();
        Validator storage validator = _capsuleValidators[validatorPubkey];

        if (!validatorContainer.verifyValidatorContainerBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }

        if (validator.status != VALIDATOR_STATUS.UNREGISTERED) {
            revert DoubleDepositedValidator(validatorPubkey);
        }

        if (_isStaleProof(proof.beaconBlockTimestamp)) {
            revert StaleValidatorContainer(validatorPubkey, proof.beaconBlockTimestamp);
        }

        if (withdrawalCredentials != bytes32(capsuleWithdrawalCredentials())) {
            revert WithdrawalCredentialsNotMatch();
        }

        _verifyValidatorContainer(validatorContainer, proof);

        validator.status = VALIDATOR_STATUS.REGISTERED;
        validator.validatorIndex = proof.validatorIndex;
        uint64 depositAmountGwei = validatorContainer.getEffectiveBalance();
        if (depositAmountGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
            depositAmount = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR * GWEI_TO_WEI;
        } else {
            depositAmount = depositAmountGwei * GWEI_TO_WEI;
        }

        _capsuleValidatorsByIndex[proof.validatorIndex] = validatorPubkey;
    }

    /// @inheritdoc IExoCapsule
    function verifyWithdrawalProof(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        BeaconChainProofs.WithdrawalProof calldata withdrawalProof
    ) external onlyGateway returns (bool partialWithdrawal, uint256 withdrawalAmount) {
        bytes32 validatorPubkey = validatorContainer.getPubkey();
        Validator storage validator = _capsuleValidators[validatorPubkey];
        uint64 withdrawalEpoch = withdrawalProof.slotRoot.getWithdrawalEpoch();
        partialWithdrawal = withdrawalEpoch < validatorContainer.getWithdrawableEpoch();
        uint256 withdrawalId = uint256(withdrawalContainer.getWithdrawalIndex());

        if (!validatorContainer.verifyValidatorContainerBasic()) {
            revert InvalidValidatorContainer(validatorPubkey);
        }
        if (validator.status == VALIDATOR_STATUS.UNREGISTERED) {
            revert UnregisteredOrWithdrawnValidatorContainer(validatorPubkey);
        }

        if (provenWithdrawal[validatorPubkey][withdrawalId]) {
            revert WithdrawalAlreadyProven(validatorPubkey, withdrawalId);
        }

        provenWithdrawal[validatorPubkey][withdrawalId] = true;

        // Validate if validator and withdrawal proof state roots are the same
        if (validatorProof.stateRoot != withdrawalProof.stateRoot) {
            revert UnmatchedValidatorAndWithdrawal(validatorProof.stateRoot, withdrawalProof.stateRoot);
        }

        _verifyValidatorContainer(validatorContainer, validatorProof);
        _verifyWithdrawalContainer(withdrawalContainer, withdrawalProof);

        uint64 withdrawalAmountGwei = withdrawalContainer.getAmount();

        if (partialWithdrawal) {
            // Immediately send ETH without sending request to Exocore side
            emit PartialWithdrawalRedeemed(validatorPubkey, withdrawalEpoch, capsuleOwner, withdrawalAmountGwei);
            _sendETH(capsuleOwner, withdrawalAmountGwei * GWEI_TO_WEI);
        } else {
            // Full withdrawal
            validator.status = VALIDATOR_STATUS.WITHDRAWN;
            // If over MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR = 32 * 1e9, then send remaining amount immediately
            emit FullWithdrawalRedeemed(validatorPubkey, withdrawalEpoch, capsuleOwner, withdrawalAmountGwei);
            if (withdrawalAmountGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
                uint256 amountToSend = (withdrawalAmountGwei - MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) * GWEI_TO_WEI;
                _sendETH(capsuleOwner, amountToSend);
                withdrawalAmount = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR * GWEI_TO_WEI;
            } else {
                withdrawalAmount = withdrawalAmountGwei * GWEI_TO_WEI;
            }
        }
    }

    /// @inheritdoc IExoCapsule
    function withdraw(uint256 amount, address payable recipient) external onlyGateway {
        require(recipient != address(0), "ExoCapsule: recipient address cannot be zero or empty");
        require(amount > 0 && amount <= withdrawableBalance, "ExoCapsule: invalid withdrawal amount");

        withdrawableBalance -= amount;
        _sendETH(recipient, amount);

        emit WithdrawalSuccess(capsuleOwner, recipient, amount);
    }

    /// @notice Withdraws the nonBeaconChainETHBalance
    /// @dev This function must be called through the gateway. @param amountToWithdraw can not be greater than
    /// the available nonBeaconChainETHBalance.
    /// @param recipient The payable destination address to which the ETH are sent.
    /// @param amountToWithdraw The amount to withdraw.
    function withdrawNonBeaconChainETHBalance(address payable recipient, uint256 amountToWithdraw)
        external
        onlyGateway
    {
        require(
            amountToWithdraw <= nonBeaconChainETHBalance,
            "ExoCapsule.withdrawNonBeaconChainETHBalance: amountToWithdraw is greater than nonBeaconChainETHBalance"
        );
        require(recipient != address(0), "ExoCapsule: recipient address cannot be zero or empty");

        nonBeaconChainETHBalance -= amountToWithdraw;
        _sendETH(recipient, amountToWithdraw);
        emit NonBeaconChainETHWithdrawn(recipient, amountToWithdraw);
    }

    /// @inheritdoc IExoCapsule
    function updateWithdrawableBalance(uint256 unlockPrincipalAmount) external onlyGateway {
        withdrawableBalance += unlockPrincipalAmount;

        emit WithdrawableBalanceUpdated(capsuleOwner, unlockPrincipalAmount);
    }

    /// @inheritdoc IExoCapsule
    function capsuleWithdrawalCredentials() public view returns (bytes memory) {
        /**
         * The withdrawal_credentials field must be such that:
         * withdrawal_credentials[:1] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
         * withdrawal_credentials[1:12] == b'\x00' * 11
         * withdrawal_credentials[12:] == eth1_withdrawal_address
         */
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }

    /// @notice Gets the beacon block root at the provided timestamp.
    /// @param timestamp The timestamp for which the block root is requested.
    /// @return The block root at the given timestamp.
    function getBeaconBlockRoot(uint256 timestamp) public view returns (bytes32) {
        bytes32 root = beaconOracle.timestampToBlockRoot(timestamp);
        if (root == bytes32(0)) {
            revert BeaconChainOracleNotUpdatedAtTime(address(beaconOracle), timestamp);
        }

        return root;
    }

    /// @notice Gets the registered validator by pubkey.
    /// @dev The validator status must be registered. Reverts if not.
    /// @param pubkey The validator's BLS12-381 public key.
    /// @return The validator object, as defined in the `ExoCapsuleStorage`.
    function getRegisteredValidatorByPubkey(bytes32 pubkey) public view returns (Validator memory) {
        Validator memory validator = _capsuleValidators[pubkey];
        if (validator.status == VALIDATOR_STATUS.UNREGISTERED) {
            revert UnregisteredValidator(pubkey);
        }

        return validator;
    }

    /// @notice Gets the registered validator by index.
    /// @dev The validator status must be registered.
    /// @param index The index of the validator.
    /// @return The validator object, as defined in the `ExoCapsuleStorage`.
    function getRegisteredValidatorByIndex(uint256 index) public view returns (Validator memory) {
        Validator memory validator = _capsuleValidators[_capsuleValidatorsByIndex[index]];
        if (validator.status == VALIDATOR_STATUS.UNREGISTERED) {
            revert UnregisteredValidator(_capsuleValidatorsByIndex[index]);
        }

        return validator;
    }

    /// @dev Sends @param amountWei of ETH to the @param recipient.
    /// @param recipient The address of the payable recipient.
    /// @param amountWei The amount of ETH to send, in wei.
    // slither-disable-next-line arbitrary-send-eth
    function _sendETH(address payable recipient, uint256 amountWei) internal nonReentrant {
        (bool sent,) = recipient.call{value: amountWei}("");
        if (!sent) {
            revert WithdrawalFailure(capsuleOwner, recipient, amountWei);
        }
    }

    /// @dev Verifies a validator container.
    /// @param validatorContainer The validator container to verify.
    /// @param proof The proof of the validator container.
    function _verifyValidatorContainer(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata proof
    ) internal view {
        bytes32 beaconBlockRoot = getBeaconBlockRoot(proof.beaconBlockTimestamp);
        bytes32 validatorContainerRoot = validatorContainer.merkleizeValidatorContainer();
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

    /// @dev Verifies a withdrawal container.
    /// @param withdrawalContainer The withdrawal container to verify.
    /// @param proof The proof of the withdrawal container.
    function _verifyWithdrawalContainer(
        bytes32[] calldata withdrawalContainer,
        BeaconChainProofs.WithdrawalProof calldata proof
    ) internal view {
        // To-do check withdrawalContainer length is valid
        bytes32 withdrawalContainerRoot = withdrawalContainer.merkleizeWithdrawalContainer();
        bool valid = withdrawalContainerRoot.isValidWithdrawalContainerRoot(proof);
        if (!valid) {
            revert InvalidWithdrawalContainer(withdrawalContainer.getValidatorIndex());
        }
    }

    /// @dev Checks if the proof is stale (too old).
    /// @param proofTimestamp The timestamp of the proof.
    function _isStaleProof(uint256 proofTimestamp) internal view returns (bool) {
        return proofTimestamp + VERIFY_BALANCE_UPDATE_WINDOW_SECONDS < block.timestamp;
    }

    /// @dev Checks if the validator has fully withdrawn.
    /// @param validatorContainer The validator container.
    /// @return True if the validator has fully withdrawn, false otherwise.
    function _hasFullyWithdrawn(bytes32[] calldata validatorContainer) internal view returns (bool) {
        return validatorContainer.getWithdrawableEpoch() <= _timestampToEpoch(block.timestamp)
            && validatorContainer.getEffectiveBalance() == 0;
    }

    /// @dev Converts a timestamp to a beacon chain epoch by calculating the number of
    /// seconds since genesis, and dividing by seconds per epoch.
    /// reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md
    /// @param timestamp The timestamp to convert.
    /// @return The epoch number.
    function _timestampToEpoch(uint256 timestamp) internal pure returns (uint64) {
        require(
            timestamp >= BEACON_CHAIN_GENESIS_TIME, "timestamp should be greater than beacon chain genesis timestamp"
        );
        return uint64((timestamp - BEACON_CHAIN_GENESIS_TIME) / BeaconChainProofs.SECONDS_PER_EPOCH);
    }

}
