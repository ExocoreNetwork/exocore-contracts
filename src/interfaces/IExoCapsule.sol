pragma solidity ^0.8.19;

import {BeaconChainProofs} from "../libraries/BeaconChainProofs.sol";

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
        bytes32[] withdrawalContainerRootProof;
    }

    function initialize(address gateway, address capsuleOwner, address beaconOracle) external;

    function verifyDepositProof(bytes32[] calldata validatorContainer, ValidatorContainerProof calldata proof)
        external
        returns (uint256);

    function verifyWithdrawalProof(
        bytes32[] calldata validatorContainer,
        ValidatorContainerProof calldata validatorProof,
        bytes32[] calldata withdrawalContainer,
        BeaconChainProofs.WithdrawalProof calldata withdrawalProof
    ) external returns (bool partialWithdrawal, uint256 withdrawalAmount);

    function withdraw(uint256 amount, address payable recipient) external;

    function updatePrincipalBalance(uint256 lastlyUpdatedPrincipalBalance) external;

    function updateWithdrawableBalance(uint256 unlockPrincipalAmount) external;

    function capsuleWithdrawalCredentials() external view returns (bytes memory);

}
