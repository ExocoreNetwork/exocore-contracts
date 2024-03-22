pragma solidity ^0.8.19;

interface IExoCapsule {
    /// @notice This struct contains the infos needed for validator container validity verification
    struct ValidatorContainerProof {
        uint64 beaconBlockTimestamp;
        bytes32 stateRoot;
        bytes32[] stateRootProof;
        bytes32[] validatorContainerRootProof;
        uint256 validatorContainerRootIndex;
    }

    struct WithdrawalContainerProof {
        uint64 beaconBlockTimestamp;
        bytes32 stateRoot;
        bytes32[] stateRootProof;
        bytes32[] withdrawalContainerProof;
        uint256 withdrawalContainerIndex;
    }

    event StakedWithThisCapsule();

    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    function deposit(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata proof
    ) external;

    function updateStakeBalance(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata proof
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