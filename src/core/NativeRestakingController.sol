pragma solidity ^0.8.19;

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {ExoCapsule} from "./ExoCapsule.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";
import {ValidatorContainer} from "../libraries/ValidatorContainer.sol";
import "../libraries/BeaconChainProofs.sol";

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
        ExoCapsule capsule = new ExoCapsule(address(this), msg.sender, beaconOracleAddress);
        ownerToCapsule[msg.sender] = capsule;

        emit CapsuleCreated(msg.sender, address(capsule));

        return address(capsule);
    }

    function depositBeaconChainValidator(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata proof
    ) external whenNotPaused {
        IExoCapsule capsule = _getCapsule(msg.sender);
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

    function verifyAndProcessWithdrawals(
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        BeaconChainProofs.WithdrawalProof[] calldata withdrawalProofs,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields,
        bytes32[][] calldata withdrawalFields
    ) external onlyWhenNotPaused {
        require(
            (validatorFields.length == validatorFieldsProofs.length) &&
                (validatorFieldsProofs.length == withdrawalProofs.length) &&
                (withdrawalProofs.length == withdrawalFields.length),
            "Inputs must be same length"
        );

        // Verify passed-in beaconStateRoot against oracle-provided block root:
        BeaconChainProofs.verifyStateRootAgainstLatestBlockRoot({
            latestBlockRoot: validatorFields.getBlockRootAtTimestamp(oracleTimestamp),
            beaconStateRoot: stateRootProof.beaconStateRoot,
            stateRootProof: stateRootProof.proof
        });

        VerifiedWithdrawal memory withdrawalSummary;
        for (uint256 i = 0; i < withdrawalFields.length; i++) {
            VerifiedWithdrawal memory verifiedWithdrawal = _verifyAndProcessWithdrawal(
                stateRootProof.beaconStateRoot,
                withdrawalProofs[i],
                validatorFieldsProofs[i],
                validatorFields[i],
                withdrawalFields[i]
            );

            withdrawalSummary.amountToSendGwei += verifiedWithdrawal.amountToSendGwei;
            withdrawalSummary.sharesDeltaGwei += verifiedWithdrawal.sharesDeltaGwei;
        }
        _sendMsgToExocore(Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE, actionArgs);
    }

    function _verifyAndProcessWithdrawal(
        bytes32 beaconStateRoot,
        BeaconChainProofs.WithdrawalProof calldata withdrawalProof,
        bytes calldata validatorFieldsProof,
        bytes32[] calldata validatorFields,
        bytes32[] calldata withdrawalFields
    )
        internal
        /**
         * Check that the provided timestamp being proven against is after the `mostRecentWithdrawalTimestamp`.
         * Without this check, there is an edge case where a user proves a past withdrawal for a validator whose funds they already withdrew,
         * as a way to "withdraw the same funds twice" without providing adequate proof.
         * Note that this check is not made using the oracleTimestamp as in the `verifyWithdrawalCredentials` proof; instead this proof
         * proof is made for the timestamp of the withdrawal, which may be within SLOTS_PER_HISTORICAL_ROOT slots of the oracleTimestamp.
         * This difference in modifier usage is OK, since it is still not possible to `verifyAndProcessWithdrawal` against a slot that occurred
         * *prior* to the proof provided in the `verifyWithdrawalCredentials` function.
         */
        proofIsForValidTimestamp(withdrawalProof.getWithdrawalTimestamp())
        returns (VerifiedWithdrawal memory)
    {
        uint64 withdrawalTimestamp = withdrawalProof.getWithdrawalTimestamp();
        bytes32 validatorPubkeyHash = validatorFields.getPubkeyHash();

        /**
         * Withdrawal processing should only be performed for "ACTIVE" or "WITHDRAWN" validators.
         * (WITHDRAWN is allowed because technically you can deposit to a validator even after it exits)
         */
        require(
            _validatorPubkeyHashToInfo[validatorPubkeyHash].status != VALIDATOR_STATUS.INACTIVE,
            "EigenPod._verifyAndProcessWithdrawal: Validator never proven to have withdrawal credentials pointed to this contract"
        );

        // Ensure we don't process the same withdrawal twice
        require(
            !provenWithdrawal[validatorPubkeyHash][withdrawalTimestamp],
            "EigenPod._verifyAndProcessWithdrawal: withdrawal has already been proven for this timestamp"
        );

        provenWithdrawal[validatorPubkeyHash][withdrawalTimestamp] = true;

        // Verifying the withdrawal against verified beaconStateRoot:
        BeaconChainProofs.verifyWithdrawal({
            beaconStateRoot: beaconStateRoot, 
            withdrawalFields: withdrawalFields, 
            withdrawalProof: withdrawalProof
        });

        uint40 validatorIndex = withdrawalFields.getValidatorIndex();

        // Verify passed-in validatorFields against verified beaconStateRoot:
        BeaconChainProofs.verifyValidatorFields({
            beaconStateRoot: beaconStateRoot,
            validatorFields: validatorFields,
            validatorFieldsProof: validatorFieldsProof,
            validatorIndex: validatorIndex
        });

        uint64 withdrawalAmountGwei = withdrawalFields.getWithdrawalAmountGwei();
        
        /**
         * If the withdrawal's epoch comes after the validator's "withdrawable epoch," we know the validator
         * has fully withdrawn, and we process this as a full withdrawal.
         */
        if (withdrawalProof.getWithdrawalEpoch() >= validatorFields.getWithdrawableEpoch()) {
            return
                _processFullWithdrawal(
                    validatorIndex,
                    validatorPubkeyHash,
                    withdrawalTimestamp,
                    podOwner,
                    withdrawalAmountGwei,
                    _validatorPubkeyHashToInfo[validatorPubkeyHash]
                );
        } else {
            return
                _processPartialWithdrawal(
                    validatorIndex,
                    withdrawalTimestamp,
                    podOwner,
                    withdrawalAmountGwei
                );
        }
    }

    function _processFullWithdrawal(
        uint40 validatorIndex,
        bytes32 validatorPubkeyHash,
        uint64 withdrawalTimestamp,
        address recipient,
        uint64 withdrawalAmountGwei,
        ValidatorInfo memory validatorInfo
    ) internal returns (VerifiedWithdrawal memory) {

        /**
         * First, determine withdrawal amounts. We need to know:
         * 1. How much can be withdrawn immediately
         * 2. How much needs to be withdrawn via the EigenLayer withdrawal queue
         */

        uint64 amountToQueueGwei;

        if (withdrawalAmountGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
            amountToQueueGwei = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR;
        } else {
            amountToQueueGwei = withdrawalAmountGwei;
        }

        /**
         * If the withdrawal is for more than the max per-validator balance, we mark 
         * the max as "withdrawable" via the queue, and withdraw the excess immediately
         */

        VerifiedWithdrawal memory verifiedWithdrawal;
        verifiedWithdrawal.amountToSendGwei = uint256(withdrawalAmountGwei - amountToQueueGwei);
        withdrawableRestakedExecutionLayerGwei += amountToQueueGwei;
        
        /**
         * Next, calculate the change in number of shares this validator is "backing":
         * - Anything that needs to go through the withdrawal queue IS backed
         * - Anything immediately withdrawn IS NOT backed
         *
         * This means that this validator is currently backing `amountToQueueGwei` shares.
         */

        verifiedWithdrawal.sharesDeltaGwei = _calculateSharesDelta({
            newAmountGwei: amountToQueueGwei,
            previousAmountGwei: validatorInfo.restakedBalanceGwei
        });

        /**
         * Finally, the validator is fully withdrawn. Update their status and place in state:
         */

        validatorInfo.restakedBalanceGwei = 0;
        validatorInfo.status = VALIDATOR_STATUS.WITHDRAWN;

        _validatorPubkeyHashToInfo[validatorPubkeyHash] = validatorInfo;

        emit FullWithdrawalRedeemed(validatorIndex, withdrawalTimestamp, recipient, withdrawalAmountGwei);

        return verifiedWithdrawal;
    }

    function _processPartialWithdrawal(
        uint40 validatorIndex,
        uint64 withdrawalTimestamp,
        address recipient,
        uint64 partialWithdrawalAmountGwei
    ) internal returns (VerifiedWithdrawal memory) {
        emit PartialWithdrawalRedeemed(
            validatorIndex,
            withdrawalTimestamp,
            recipient,
            partialWithdrawalAmountGwei
        );

        sumOfPartialWithdrawalsClaimedGwei += partialWithdrawalAmountGwei;

        // For partial withdrawals, the withdrawal amount is immediately sent to the pod owner
        return
            VerifiedWithdrawal({
                amountToSendGwei: uint256(partialWithdrawalAmountGwei),
                sharesDeltaGwei: 0
            });
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
