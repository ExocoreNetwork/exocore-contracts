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
    uint256 internal constant BEACON_BLOCK_HEADER_FIELD_TREE_HEIGHT = 3;

    uint256 internal constant BEACON_BLOCK_BODY_FIELD_TREE_HEIGHT = 4;

    uint256 internal constant BEACON_STATE_FIELD_TREE_HEIGHT = 5;

    uint256 internal constant VALIDATOR_TREE_HEIGHT = 40;

    // MAX_WITHDRAWALS_PER_PAYLOAD = 2**4, making tree height = 4
    uint256 internal constant WITHDRAWALS_TREE_HEIGHT = 4;

    // in beacon block body
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconblockbody
    uint256 internal constant EXECUTION_PAYLOAD_INDEX = 9;

    // in beacon block header
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
    uint256 internal constant STATE_ROOT_INDEX = 3;
    uint256 internal constant BODY_ROOT_INDEX = 4;
    // in beacon state
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#beaconstate
    uint256 internal constant VALIDATOR_TREE_ROOT_INDEX = 11;

    //in execution payload
    uint256 internal constant WITHDRAWALS_INDEX = 14;

    //Misc Constants

    /// @notice The number of slots each epoch in the beacon chain
    uint64 internal constant SLOTS_PER_EPOCH = 32;

    /// @notice The number of seconds in a slot in the beacon chain
    uint64 internal constant SECONDS_PER_SLOT = 12;

    /// @notice Number of seconds per epoch: 384 == 32 slots/epoch * 12 seconds/slot
    // slither-disable-next-line unused-state
    uint64 internal constant SECONDS_PER_EPOCH = SLOTS_PER_EPOCH * SECONDS_PER_SLOT;

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
        bytes32[] calldata executionPayloadRootProof
    ) internal view returns (bool valid) {
        bool validExecutionPayloadRoot =
            isValidExecutionPayloadRoot(executionPayloadRoot, beaconBlockRoot, executionPayloadRootProof);
        bool validWCRootAgainstExecutionPayloadRoot = isValidWCRootAgainstExecutionPayloadRoot(
            withdrawalContainerRoot, executionPayloadRoot, withdrawalContainerRootProof, withdrawalIndex
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
        uint256 withdrawalIndex
    ) internal view returns (bool) {
        require(
            withdrawalContainerRootProof.length == (VALIDATOR_TREE_HEIGHT + 1) + BEACON_STATE_FIELD_TREE_HEIGHT,
            "validator container root proof should have 46 nodes"
        );

        uint256 leafIndex = (WITHDRAWALS_INDEX << (WITHDRAWALS_TREE_HEIGHT + 1)) | uint256(withdrawalIndex);

        return Merkle.verifyInclusionSha256({
            proof: withdrawalContainerRootProof,
            root: executionPayloadRoot,
            leaf: withdrawalContainerRoot,
            index: leafIndex
        });
    }

}
