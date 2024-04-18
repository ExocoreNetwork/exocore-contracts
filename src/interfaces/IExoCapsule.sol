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
        bytes32 executionPayloadRoot;
        bytes32[] executionPayloadRootProof;
        bytes32[] withdrawalContainerRootProof;
        uint256 withdrawalContainerRootIndex;
    }

    event StakedWithThisCapsule();

    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    function verifyDepositProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata proof
    ) external;

    function verifyPartialWithdrawalProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external;

    function verifyFullWithdrawalProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external;

    function withdraw(uint256 amount, address recipient) external;
}