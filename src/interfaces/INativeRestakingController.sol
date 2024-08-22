// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";
import {IBaseRestakingController} from "./IBaseRestakingController.sol";

/// @title INativeRestakingController
/// @author ExocoreNetwork
/// @notice Interface for the NativeRestakingController contract.
/// @dev Provides methods for interacting with the Ethereum beacon chain and Exocore network, including staking,
/// creating ExoCapsules, and processing withdrawals.
interface INativeRestakingController is IBaseRestakingController {

    /// @notice Deposits to a beacon chain validator and sets withdrawal credentials to the staker's ExoCapsule contract
    /// address.
    /// @dev If the ExoCapsule contract does not exist, it will be created.
    /// @param pubkey The BLS pubkey of the beacon chain validator.
    /// @param signature The BLS signature.
    /// @param depositDataRoot The SHA-256 hash of the SSZ-encoded DepositData object, used as a protection against
    /// malformed input.
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /// @notice Creates an ExoCapsule owned by the Ethereum native restaker.
    /// @dev This should be done before staking to the beacon chain.
    /// @return capsule The address of the created ExoCapsule.
    function createExoCapsule() external returns (address capsule);

    /// @notice Deposits ETH staked on the Ethereum beacon chain to the Exocore network for future restaking.
    /// @dev Before depositing, the staker should have created an ExoCapsule and set the validator's withdrawal
    /// credentials to it.
    /// The effective balance of `validatorContainer` will be credited as the deposited value by the Exocore network.
    /// @param validatorContainer The data structure included in the `BeaconState` of `BeaconBlock` that contains beacon
    /// chain validator information.
    /// @param proof The proof needed to verify the validator container.
    function depositBeaconChainValidator(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata proof
    ) external payable;

    /// @notice Processes a partial withdrawal from the beacon chain to an ExoCapsule contract.
    /// @dev This function is called with `validatorContainer`, `withdrawalContainer`, and corresponding proofs to prove
    /// the partial withdrawal.
    /// The withdrawn ETH will be unlocked and claimable for the ExoCapsule owner.
    /// @param validatorContainer The data structure included in the `BeaconState` of `BeaconBlock` that contains beacon
    /// chain validator information.
    /// @param validatorProof The merkle proof needed to verify that `validatorContainer` is included in a beacon block
    /// root.
    /// @param withdrawalContainer The data structure included in the `ExecutionPayload` of `BeaconBlockBody` that
    /// contains withdrawals from the beacon chain to the execution layer.
    /// @param withdrawalProof The merkle proof needed to verify that `withdrawalContainer` is included in a beacon
    /// block root.
    function processBeaconChainWithdrawal(
        bytes32[] calldata validatorContainer,
        BeaconChainProofs.ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        BeaconChainProofs.WithdrawalProof calldata withdrawalProof
    ) external payable;

}
