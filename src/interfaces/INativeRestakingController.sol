pragma solidity ^0.8.19;

import {IExoCapsule} from "./IExoCapsule.sol";
import {IBaseRestakingController} from "./IBaseRestakingController.sol";

interface INativeRestakingController is IBaseRestakingController {
    /// *** function signatures for staker operations ***

    /**
     * @notice Stakers call this function to deposit to beacon chain validator, and point withdrawal_credentials of 
     * beacon chain validator to staker's ExoCapsule contract address. An ExoCapsule contract owned by staker would
     * be created if it does not exist.
     * @param pubkey the BLS pubkey of beacon chain validator
     * @param signature the BLS signature 
     * @param depositDataRoot The SHA-256 hash of the SSZ-encoded DepositData object.
     * Used as a protection against malformed input.
     */
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /**
     * @notice Ethereum native restaker could call this function to create owned ExoCapsule before staking to beacon chain.
     */
    function createExoCapsule() external returns (address capsule);

    /**
     * @notice This is called to deposit ETH that is staked on Ethereum beacon chain to Exocore network to be restaked in future
     * @dev Before deposit, staker should have created the ExoCapsule that it owns and point the validator's withdrawal crendentials
     * to the ExoCapsule owned by staker. The effective balance of `validatorContainer` would be credited as deposited value by Exocore network.
     * @ param 
     */
    function depositBeaconChainValidator(bytes32[] calldata validatorContainer, IExoCapsule.ValidatorContainerProof calldata proof) payable external;

    /**
     * @notice When a beacon chain partial withdrawal to an ExoCapsule contract happens(the withdrawal time is less than validator's withdrawable_epoch), 
     * this function could be called with `validatorContainer`, `withdrawalContainer` and corresponding proofs to prove this partial withdrawal 
     * from beacon chain is done and unlock withdrawn ETH to be claimable for ExoCapsule owner.
     * @param validatorContainer is the data structure included in `BeaconState` of `BeaconBlock` that contains beacon chain validator information,
     * refer to: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
     * @param validatorProof is the merkle proof needed for verifying that `validatorContainer` is included in some beacon block root.
     * @param withdrawalContainer is the data structure included in `ExecutionPayload` of `BeaconBlockBody` that contains
     * withdrawals from beacon chain to execution layer(partial/full), refer to:
     * https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#withdrawal
     * @param withdrawalProof is the merkle proof needed for verifying that `withdrawalContainer` is included in some beacon block root.
     */
    function processBeaconChainPartialWithdrawal(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        IExoCapsule.WithdrawalContainerProof calldata withdrawalProof
    ) payable external;

    /**
     * @notice When a beacon chain full withdrawal to this capsule contract happens(the withdrawal time is euqal to or greater than 
     * validator's withdrawable_epoch), this function could be called with `validatorContainer`, `withdrawalContainer` and corresponding 
     * proofs to prove this full withdrawal from beacon chain is done, send withdrawal request to Exocore network to be processed.
     * After Exocore network finishs dealing with withdrawal request and sending back the response, ExoCapsule would unlock corresponding ETH
     * in response to be cliamable for ExoCapsule owner.
     * @param validatorContainer is the data structure included in `BeaconState` of `BeaconBlock` that contains beacon chain validator information,
     * refer to: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
     * @param validatorProof is the merkle proof needed for verifying that `validatorContainer` is included in some beacon block root.
     * @param withdrawalContainer is the data structure included in `ExecutionPayload` of `BeaconBlockBody` that contains
     * withdrawals from beacon chain to execution layer(partial/full), refer to:
     * https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#withdrawal
     * @param withdrawalProof is the merkle proof needed for verifying that `withdrawalContainer` is included in some beacon block root.
     */
    function processBeaconChainFullWithdrawal(
        bytes32[] calldata validatorContainer,
        IExoCapsule.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        IExoCapsule.WithdrawalContainerProof calldata withdrawalProof
    ) payable external;
}
