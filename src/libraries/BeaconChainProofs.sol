pragma solidity ^0.8.0;

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
    uint256 internal constant NUM_BEACON_BLOCK_HEADER_FIELDS = 5;
    uint256 internal constant BEACON_BLOCK_HEADER_FIELD_TREE_HEIGHT = 3;

    uint256 internal constant NUM_BEACON_BLOCK_BODY_FIELDS = 11;
    uint256 internal constant BEACON_BLOCK_BODY_FIELD_TREE_HEIGHT = 4;

    uint256 internal constant NUM_BEACON_STATE_FIELDS = 21;
    uint256 internal constant BEACON_STATE_FIELD_TREE_HEIGHT = 5;

    uint256 internal constant NUM_ETH1_DATA_FIELDS = 3;
    uint256 internal constant ETH1_DATA_FIELD_TREE_HEIGHT = 2;

    uint256 internal constant NUM_VALIDATOR_FIELDS = 8;
    uint256 internal constant VALIDATOR_FIELD_TREE_HEIGHT = 3;

    uint256 internal constant NUM_EXECUTION_PAYLOAD_HEADER_FIELDS = 15;
    uint256 internal constant DENEB_FORK_TIMESTAMP = 1_710_338_135;
    uint256 internal constant EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_CAPELLA = 4;
    uint256 internal constant EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_DENEB = 5; // After deneb hard fork, it's
        // increased from 4 to 5

    uint256 internal constant NUM_EXECUTION_PAYLOAD_FIELDS = 15;
    uint256 internal constant EXECUTION_PAYLOAD_FIELD_TREE_HEIGHT = 4;

    // HISTORICAL_ROOTS_LIMIT	 = 2**24, so tree height is 24
    uint256 internal constant HISTORICAL_ROOTS_TREE_HEIGHT = 24;

    // HISTORICAL_BATCH is root of state_roots and block_root, so number of leaves =  2^1
    uint256 internal constant HISTORICAL_BATCH_TREE_HEIGHT = 1;

    // SLOTS_PER_HISTORICAL_ROOT = 2**13, so tree height is 13
    uint256 internal constant STATE_ROOTS_TREE_HEIGHT = 13;
    uint256 internal constant BLOCK_ROOTS_TREE_HEIGHT = 13;

    //HISTORICAL_ROOTS_LIMIT = 2**24, so tree height is 24
    uint256 internal constant HISTORICAL_SUMMARIES_TREE_HEIGHT = 24;

    //Index of block_summary_root in historical_summary container
    uint256 internal constant BLOCK_SUMMARY_ROOT_INDEX = 0;

    uint256 internal constant NUM_WITHDRAWAL_FIELDS = 4;
    // tree height for hash tree of an individual withdrawal container
    uint256 internal constant WITHDRAWAL_FIELD_TREE_HEIGHT = 2;

    uint256 internal constant VALIDATOR_TREE_HEIGHT = 40;

    // MAX_WITHDRAWALS_PER_PAYLOAD = 2**4, making tree height = 4
    uint256 internal constant WITHDRAWALS_TREE_HEIGHT = 4;

    // in beacon block body
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconblockbody
    uint256 internal constant EXECUTION_PAYLOAD_INDEX = 9;

    // in beacon block header
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
    uint256 internal constant SLOT_INDEX = 0;
    uint256 internal constant PROPOSER_INDEX_INDEX = 1;
    uint256 internal constant STATE_ROOT_INDEX = 3;
    uint256 internal constant BODY_ROOT_INDEX = 4;
    // in beacon state
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconstate
    uint256 internal constant HISTORICAL_BATCH_STATE_ROOT_INDEX = 1;
    uint256 internal constant BEACON_STATE_SLOT_INDEX = 2;
    uint256 internal constant LATEST_BLOCK_HEADER_ROOT_INDEX = 4;
    uint256 internal constant BLOCK_ROOTS_INDEX = 5;
    uint256 internal constant STATE_ROOTS_INDEX = 6;
    uint256 internal constant HISTORICAL_ROOTS_INDEX = 7;
    uint256 internal constant ETH_1_ROOT_INDEX = 8;
    uint256 internal constant VALIDATOR_TREE_ROOT_INDEX = 11;
    uint256 internal constant EXECUTION_PAYLOAD_HEADER_INDEX = 24;
    uint256 internal constant HISTORICAL_SUMMARIES_INDEX = 27;

    // in validator
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    uint256 internal constant VALIDATOR_PUBKEY_INDEX = 0;
    uint256 internal constant VALIDATOR_WITHDRAWAL_CREDENTIALS_INDEX = 1;
    uint256 internal constant VALIDATOR_BALANCE_INDEX = 2;
    uint256 internal constant VALIDATOR_SLASHED_INDEX = 3;
    uint256 internal constant VALIDATOR_WITHDRAWABLE_EPOCH_INDEX = 7;

    // in execution payload header
    uint256 internal constant TIMESTAMP_INDEX = 9;
    uint256 internal constant WITHDRAWALS_ROOT_INDEX = 14;

    //in execution payload
    uint256 internal constant WITHDRAWALS_INDEX = 14;

    // in withdrawal
    uint256 internal constant WITHDRAWAL_VALIDATOR_INDEX_INDEX = 1;
    uint256 internal constant WITHDRAWAL_VALIDATOR_AMOUNT_INDEX = 3;

    //In historicalBatch
    uint256 internal constant HISTORICALBATCH_STATEROOTS_INDEX = 1;

    //Misc Constants

    /// @notice The number of slots each epoch in the beacon chain
    uint64 internal constant SLOTS_PER_EPOCH = 32;

    /// @notice The number of seconds in a slot in the beacon chain
    uint64 internal constant SECONDS_PER_SLOT = 12;

    /// @notice Number of seconds per epoch: 384 == 32 slots/epoch * 12 seconds/slot
    uint64 internal constant SECONDS_PER_EPOCH = SLOTS_PER_EPOCH * SECONDS_PER_SLOT;

    bytes8 internal constant UINT64_MASK = 0xffffffffffffffff;

    /// @notice This struct contains the merkle proofs and leaves needed to verify a partial/full withdrawal
    struct WithdrawalProof {
        bytes withdrawalProof;
        bytes slotProof;
        bytes executionPayloadProof;
        bytes timestampProof;
        bytes historicalSummaryBlockRootProof;
        uint64 blockRootIndex;
        uint64 historicalSummaryIndex;
        uint64 withdrawalIndex;
        bytes32 blockRoot;
        bytes32 slotRoot;
        bytes32 timestampRoot;
        bytes32 executionPayloadRoot;
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

    function isValidWithdrawalContainerRoot(
        bytes32 withdrawalContainerRoot,
        bytes32[] calldata withdrawalContainerRootProof,
        uint256 withdrawalIndex,
        bytes32 beaconBlockRoot,
        bytes32 executionPayloadRoot,
        bytes32[] calldata executionPayloadRootProof,
        uint256 beaconBlockTimestamp
    ) internal view returns (bool valid) {
        bool validExecutionPayloadRoot =
            isValidExecutionPayloadRoot(executionPayloadRoot, beaconBlockRoot, executionPayloadRootProof);

        bool validWCRootAgainstExecutionPayloadRoot = isValidWCRootAgainstExecutionPayloadRoot(
            withdrawalContainerRoot,
            executionPayloadRoot,
            withdrawalContainerRootProof,
            withdrawalIndex,
            beaconBlockTimestamp
        );

        if (validExecutionPayloadRoot && validWCRootAgainstExecutionPayloadRoot) {
            valid = true;
        }
    }

    function isValidExecutionPayloadRoot(
        bytes32 executionPayloadRoot,
        bytes32 beaconBlockRoot,
        bytes32[] calldata executionPayloadRootProof
    ) internal view returns (bool) {
        require(
            executionPayloadRootProof.length
                == BEACON_BLOCK_HEADER_FIELD_TREE_HEIGHT + BEACON_BLOCK_BODY_FIELD_TREE_HEIGHT,
            "state root proof should have 3 nodes"
        );

        uint256 leafIndex = (BODY_ROOT_INDEX << (BEACON_BLOCK_BODY_FIELD_TREE_HEIGHT)) | EXECUTION_PAYLOAD_INDEX;

        return Merkle.verifyInclusionSha256({
            proof: executionPayloadRootProof,
            root: beaconBlockRoot,
            leaf: executionPayloadRoot,
            index: leafIndex
        });
    }

    function isValidWCRootAgainstExecutionPayloadRoot(
        bytes32 withdrawalContainerRoot,
        bytes32 executionPayloadRoot,
        bytes32[] calldata withdrawalContainerRootProof,
        uint256 withdrawalIndex,
        uint256 beaconBlockTimestamp
    ) internal view returns (bool) {
        uint256 executionPayloadHeaderFieldTreeHeight = (beaconBlockTimestamp < DENEB_FORK_TIMESTAMP)
            ? EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_CAPELLA
            : EXECUTION_PAYLOAD_HEADER_FIELD_TREE_HEIGHT_DENEB;

        require(
            withdrawalContainerRootProof.length == (executionPayloadHeaderFieldTreeHeight + WITHDRAWALS_TREE_HEIGHT + 1),
            "withdrawalProof has incorrect length"
        );

        uint256 leafIndex = (WITHDRAWALS_INDEX << (WITHDRAWALS_TREE_HEIGHT + 1)) | uint256(withdrawalIndex);

        return Merkle.verifyInclusionSha256({
            proof: withdrawalContainerRootProof,
            root: executionPayloadRoot,
            leaf: withdrawalContainerRoot,
            index: leafIndex
        });
    }

    function isValidHistoricalSummaryRoot(
        bytes32 beaconStateRoot,
        bytes32[] calldata historicalSummaryBlockRootProof,
        uint256 historicalSummaryIndex,
        bytes32 beaconBlockRoot,
        uint256 blockRootIndex
    ) internal view returns (bool) {
        require(
            historicalSummaryBlockRootProof.length
                == (BEACON_STATE_FIELD_TREE_HEIGHT + (HISTORICAL_SUMMARIES_TREE_HEIGHT + 1) + 1 + (BLOCK_ROOTS_TREE_HEIGHT)),
            "historicalSummaryBlockRootProof has incorrect length"
        );
        /**
         * Note: Here, the "1" in "1 + (BLOCK_ROOTS_TREE_HEIGHT)" signifies that extra step of choosing the
         * "block_root_summary" within the individual
         * "historical_summary". Everywhere else it signifies merkelize_with_mixin, where the length of an array is
         * hashed with the root of the array,
         * but not here.
         */
        uint256 historicalBlockHeaderIndex = (
            HISTORICAL_SUMMARIES_INDEX << ((HISTORICAL_SUMMARIES_TREE_HEIGHT + 1) + 1 + (BLOCK_ROOTS_TREE_HEIGHT))
        ) | (historicalSummaryIndex << (1 + (BLOCK_ROOTS_TREE_HEIGHT)))
            | (BLOCK_SUMMARY_ROOT_INDEX << (BLOCK_ROOTS_TREE_HEIGHT)) | blockRootIndex;

        return Merkle.verifyInclusionSha256({
            proof: historicalSummaryBlockRootProof,
            root: beaconStateRoot,
            leaf: beaconBlockRoot,
            index: historicalBlockHeaderIndex
        });
    }

}
