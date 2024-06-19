pragma solidity ^0.8.19;

interface IExoCapsule {

    /// @notice This struct contains the infos needed for validator container validity verification
    struct ValidatorContainerProof {
        uint256 beaconBlockTimestamp;
        bytes32 stateRoot;
        bytes32[] stateRootProof;
        bytes32[] validatorContainerRootProof;
        uint256 validatorIndex;
    }

    struct WithdrawalContainerProof {
        uint256 beaconBlockTimestamp;
        bytes32 executionPayloadRoot;
        bytes32[] executionPayloadRootProof;
        bytes32[] withdrawalContainerRootProof;
        uint256 withdrawalIndex;
    }

    function verifyDepositProof(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof)
        external;

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

    function withdraw(uint256 amount, address payable recipient) external;

    function updatePrincipalBalance(uint256 lastlyUpdatedPrincipalBalance) external;

    function updateWithdrawableBalance(uint256 unlockPrincipalAmount) external;

    function capsuleWithdrawalCredentials() external view returns (bytes memory);

}
