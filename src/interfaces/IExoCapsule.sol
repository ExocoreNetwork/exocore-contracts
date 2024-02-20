pragma solidity ^0.8.19;

interface IExoCapsule {
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    function deposit(
        uint64 beaconBlockTimestamp,
        bytes32 beaconStateRoot,
        bytes[] calldata beaconStateRootProof,
        bytes32[][] calldata validatorFields,
        uint40[] calldata validatorProofIndices,
        bytes[] calldata validatorFieldsProof
    ) external;

    function updateStakeBalance(
        uint64 beaconBlockTimestamp,
        bytes32 beaconStateRoot,
        bytes[] calldata beaconStateRootProof,
        bytes32[][] calldata validatorFields,
        uint40[] calldata validatorProofIndices,
        bytes[] calldata validatorFieldsProof
    ) external;

    function withdraw(
        uint64 beaconBlockTimestamp,
        bytes32 beaconStateRoot,
        bytes[] calldata beaconStateRootProof,
        bytes32[][] calldata withdrawalFields,
        uint40[] calldata withdrawalProofIndices,
        bytes[] calldata withdrawalFieldsProof
    ) external;
}