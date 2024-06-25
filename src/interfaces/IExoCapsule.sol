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
        bytes32 stateRoot;
        bytes32 executionPayloadRoot;
        bytes32[] executionPayloadRootProof;
        bytes32[] withdrawalContainerRootProof;
        bytes32[] historicalSummaryBlockRootProof;
        uint256 historicalSummaryIndex;
        uint256 blockRootIndex;
        uint256 withdrawalIndex;
    }

    function initialize(address gateway, address capsuleOwner, address beaconOracle) external;

    function verifyDepositProof(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof)
        external;

    function verifyWithdrawalProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        WithdrawalContainerProof calldata withdrawalProof
    ) external returns (bool partialWithdrawal, uint256 withdrawalAmount);

    function withdraw(uint256 amount, address payable recipient) external;

    function updatePrincipalBalance(uint256 lastlyUpdatedPrincipalBalance) external;

    function updateWithdrawableBalance(uint256 unlockPrincipalAmount) external;

    function capsuleWithdrawalCredentials() external view returns (bytes memory);

}
