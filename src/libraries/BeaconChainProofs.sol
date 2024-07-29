// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Endian} from "../libraries/Endian.sol";
import {Merkle} from "./Merkle.sol";

// Utility library for parsing and PHASE0 beacon chain block headers
// SSZ
// Spec: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md#merkleization
// BeaconBlockHeader
// Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
// BeaconState
// Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconstate

library BeaconChainProofs {

    // constants are the number of fields and the heights of the different merkle trees used in merkleizing
    // beacon chain containers
    uint256 internal constant BEACON_BLOCK_HEADER_FIELD_TREE_HEIGHT = 3;

    uint256 internal constant BEACON_BLOCK_BODY_FIELD_TREE_HEIGHT = 4;

    uint256 internal constant BEACON_STATE_FIELD_TREE_HEIGHT = 5;

    uint256 internal constant DENEB_FORK_TIMESTAMP = 1_710_338_135;
    uint256 internal constant EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_CAPELLA = 4;
    uint256 internal constant EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_DENEB = 5; // After deneb hard fork, it's

    // increased from 4 to 5
    // SLOTS_PER_HISTORICAL_ROOT = 2**13, so tree height is 13
    uint256 internal constant BLOCK_ROOTS_TREE_HEIGHT = 13;

    //Index of block_summary_root in historical_summary container
    uint256 internal constant BLOCK_SUMMARY_ROOT_INDEX = 0;
    //HISTORICAL_ROOTS_LIMIT = 2**24, so tree height is 24
    uint256 internal constant HISTORICAL_SUMMARIES_TREE_HEIGHT = 24;

    uint256 internal constant VALIDATOR_TREE_HEIGHT = 40;

    // MAX_WITHDRAWALS_PER_PAYLOAD = 2**4, making tree height = 4
    uint256 internal constant WITHDRAWALS_TREE_HEIGHT = 4;

    // in beacon block body
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconblockbody
    uint256 internal constant EXECUTION_PAYLOAD_INDEX = 9;

    uint256 internal constant SLOT_INDEX = 0;
    // in beacon block header
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
    uint256 internal constant STATE_ROOT_INDEX = 3;
    uint256 internal constant BODY_ROOT_INDEX = 4;
    // in beacon state
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconstate
    uint256 internal constant VALIDATOR_TREE_ROOT_INDEX = 11;
    uint256 internal constant HISTORICAL_SUMMARIES_INDEX = 27;

    // in execution payload header
    uint256 internal constant TIMESTAMP_INDEX = 9;
    //in execution payload
    uint256 internal constant WITHDRAWALS_INDEX = 14;

    //Misc Constants

    /// @notice The number of slots each epoch in the beacon chain
    uint64 internal constant SLOTS_PER_EPOCH = 32;

    /// @notice The number of seconds in a slot in the beacon chain
    uint64 internal constant SECONDS_PER_SLOT = 12;

    /// @notice Number of seconds per epoch: 384 == 32 slots/epoch * 12 seconds/slot
    /// @dev This constant would be used by other contracts that import this library
    // slither-disable-next-line unused-state
    uint64 internal constant SECONDS_PER_EPOCH = SLOTS_PER_EPOCH * SECONDS_PER_SLOT;

    /// @notice This struct contains the merkle proofs and leaves needed to verify a partial/full withdrawal
    struct WithdrawalProof {
        bytes32[] withdrawalContainerRootProof;
        bytes32[] slotProof;
        bytes32[] executionPayloadRootProof;
        bytes32[] timestampProof;
        bytes32[] historicalSummaryBlockRootProof;
        uint256 blockRootIndex;
        uint256 historicalSummaryIndex;
        uint256 withdrawalIndex;
        bytes32 blockRoot;
        bytes32 slotRoot;
        bytes32 timestampRoot;
        bytes32 executionPayloadRoot;
        bytes32 stateRoot;
    }

    /// @notice This struct contains the root and proof for verifying the state root against the oracle block root
    struct StateRootProof {
        bytes32 beaconStateRoot;
        bytes proof;
    }

    function isValidValidatorContainerRoot(
        bytes32 validatorContainerRoot,
        bytes32[] calldata validatorContainerRootProof,
        uint256 validatorIndex,
        bytes32 beaconBlockRoot,
        bytes32 stateRoot,
        bytes32[] calldata stateRootProof
    ) internal view returns (bool valid) {
        bool validStateRoot = isValidStateRoot(stateRoot, beaconBlockRoot, stateRootProof);
        bool validVCRootAgainstStateRoot = isValidVCRootAgainstStateRoot(
            validatorContainerRoot, stateRoot, validatorContainerRootProof, validatorIndex
        );
        if (validStateRoot && validVCRootAgainstStateRoot) {
            valid = true;
        }
    }

    function isValidStateRoot(bytes32 stateRoot, bytes32 beaconBlockRoot, bytes32[] calldata stateRootProof)
        internal
        view
        returns (bool)
    {
        require(stateRootProof.length == BEACON_BLOCK_HEADER_FIELD_TREE_HEIGHT, "state root proof should have 3 nodes");

        return Merkle.verifyInclusionSha256({
            proof: stateRootProof,
            root: beaconBlockRoot,
            leaf: stateRoot,
            index: STATE_ROOT_INDEX
        });
    }

    function isValidVCRootAgainstStateRoot(
        bytes32 validatorContainerRoot,
        bytes32 stateRoot,
        bytes32[] calldata validatorContainerRootProof,
        uint256 validatorIndex
    ) internal view returns (bool) {
        require(
            validatorContainerRootProof.length == (VALIDATOR_TREE_HEIGHT + 1) + BEACON_STATE_FIELD_TREE_HEIGHT,
            "validator container root proof should have 46 nodes"
        );

        uint256 leafIndex = (VALIDATOR_TREE_ROOT_INDEX << (VALIDATOR_TREE_HEIGHT + 1)) | uint256(validatorIndex);

        return Merkle.verifyInclusionSha256({
            proof: validatorContainerRootProof,
            root: stateRoot,
            leaf: validatorContainerRoot,
            index: leafIndex
        });
    }

    function isValidWithdrawalContainerRoot(bytes32 withdrawalContainerRoot, WithdrawalProof calldata proof)
        internal
        view
        returns (bool valid)
    {
        require(proof.blockRootIndex < 2 ** BLOCK_ROOTS_TREE_HEIGHT, "blockRootIndex too large");
        require(proof.withdrawalIndex < 2 ** WITHDRAWALS_TREE_HEIGHT, "withdrawalIndex too large");
        require(
            proof.historicalSummaryIndex < 2 ** HISTORICAL_SUMMARIES_TREE_HEIGHT, "historicalSummaryIndex too large"
        );
        bool validExecutionPayloadRoot = isValidExecutionPayloadRoot(proof);
        bool validHistoricalSummary = isValidHistoricalSummaryRoot(proof);
        bool validWCRootAgainstExecutionPayloadRoot = isValidWCRootAgainstBlockRoot(proof, withdrawalContainerRoot);
        if (validExecutionPayloadRoot && validHistoricalSummary && validWCRootAgainstExecutionPayloadRoot) {
            valid = true;
        }
    }

    function isValidExecutionPayloadRoot(WithdrawalProof calldata withdrawalProof) internal pure returns (bool) {
        uint256 withdrawalTimestamp = getWithdrawalTimestamp(withdrawalProof);
        // Post deneb hard fork, executionPayloadHeader fields increased
        uint256 executionPayloadHeaderFieldTreeHeight = withdrawalTimestamp < DENEB_FORK_TIMESTAMP
            ? EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_CAPELLA
            : EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_DENEB;
        require(
            withdrawalProof.withdrawalContainerRootProof.length
                == executionPayloadHeaderFieldTreeHeight + WITHDRAWALS_TREE_HEIGHT + 1,
            "wcRootProof has incorrect length"
        );
        require(
            withdrawalProof.executionPayloadRootProof.length
                == BEACON_BLOCK_HEADER_FIELD_TREE_HEIGHT + BEACON_BLOCK_BODY_FIELD_TREE_HEIGHT,
            "executionPayloadRootProof has incorrect length"
        );
        require(
            withdrawalProof.slotProof.length == BEACON_BLOCK_HEADER_FIELD_TREE_HEIGHT, "slotProof has incorrect length"
        );
        require(
            withdrawalProof.timestampProof.length == executionPayloadHeaderFieldTreeHeight,
            "timestampProof has incorrect length"
        );
        return true;
    }

    function isValidWCRootAgainstBlockRoot(WithdrawalProof calldata withdrawalProof, bytes32 withdrawalContainerRoot)
        internal
        view
        returns (bool)
    {
        //Next we verify the slot against the blockRoot
        require(
            Merkle.verifyInclusionSha256({
                proof: withdrawalProof.slotProof,
                root: withdrawalProof.blockRoot,
                leaf: withdrawalProof.slotRoot,
                index: SLOT_INDEX
            }),
            "Invalid slot merkle proof"
        );

        // Verify the executionPayloadRoot against the blockRoot
        uint256 executionPayloadIndex =
            (BODY_ROOT_INDEX << (BEACON_BLOCK_BODY_FIELD_TREE_HEIGHT)) | EXECUTION_PAYLOAD_INDEX;
        require(
            Merkle.verifyInclusionSha256({
                proof: withdrawalProof.executionPayloadRootProof,
                root: withdrawalProof.blockRoot,
                leaf: withdrawalProof.executionPayloadRoot,
                index: executionPayloadIndex
            }),
            "Invalid executionPayload proof"
        );

        // Verify the timestampRoot against the executionPayload root
        require(
            Merkle.verifyInclusionSha256({
                proof: withdrawalProof.timestampProof,
                root: withdrawalProof.executionPayloadRoot,
                leaf: withdrawalProof.timestampRoot,
                index: TIMESTAMP_INDEX
            }),
            "Invalid timestamp proof"
        );

        /**
         * Next we verify the withdrawal fields against the executionPayloadRoot:
         * First we compute the withdrawal_index, then we merkleize the
         * withdrawalFields container to calculate the withdrawalRoot.
         *
         * Note: Merkleization of the withdrawals root tree uses MerkleizeWithMixin, i.e., the length of the array
         * is hashed with the root of
         * the array.  Thus we shift the WITHDRAWALS_INDEX over by WITHDRAWALS_TREE_HEIGHT + 1 and not just
         * WITHDRAWALS_TREE_HEIGHT.
         */
        uint256 withdrawalIndex =
            (WITHDRAWALS_INDEX << (WITHDRAWALS_TREE_HEIGHT + 1)) | uint256(withdrawalProof.withdrawalIndex);

        return Merkle.verifyInclusionSha256({
            proof: withdrawalProof.withdrawalContainerRootProof,
            root: withdrawalProof.executionPayloadRoot,
            leaf: withdrawalContainerRoot,
            index: withdrawalIndex
        });
    }

    function isValidHistoricalSummaryRoot(WithdrawalProof calldata withdrawalProof) internal view returns (bool) {
        require(
            withdrawalProof.historicalSummaryBlockRootProof.length
                == BEACON_STATE_FIELD_TREE_HEIGHT + (HISTORICAL_SUMMARIES_TREE_HEIGHT + 1) + 1 + (BLOCK_ROOTS_TREE_HEIGHT),
            "historicalSummaryBlockRootProof has incorrect length"
        );

        uint256 historicalBlockHeaderIndex = (
            HISTORICAL_SUMMARIES_INDEX << ((HISTORICAL_SUMMARIES_TREE_HEIGHT + 1) + 1 + (BLOCK_ROOTS_TREE_HEIGHT))
        ) | (withdrawalProof.historicalSummaryIndex << (1 + (BLOCK_ROOTS_TREE_HEIGHT)))
            | (BLOCK_SUMMARY_ROOT_INDEX << (BLOCK_ROOTS_TREE_HEIGHT)) | withdrawalProof.blockRootIndex;

        return Merkle.verifyInclusionSha256({
            proof: withdrawalProof.historicalSummaryBlockRootProof,
            root: withdrawalProof.stateRoot,
            leaf: withdrawalProof.blockRoot,
            index: historicalBlockHeaderIndex
        });
    }
    /**
     * @dev Retrieve the withdrawal timestamp
     */

    function getWithdrawalTimestamp(WithdrawalProof calldata withdrawalProof) internal pure returns (uint64) {
        return Endian.fromLittleEndianUint64(withdrawalProof.timestampRoot);
    }

    /**
     * @dev Converts the withdrawal's slot to an epoch
     */
    function getWithdrawalEpoch(bytes32 slotRoot) internal pure returns (uint64) {
        return Endian.fromLittleEndianUint64(slotRoot) / SLOTS_PER_EPOCH;
    }

}
