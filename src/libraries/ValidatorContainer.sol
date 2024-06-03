pragma solidity ^0.8.19;

import "../libraries/Endian.sol";

/**
 * class Validator(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32  # Commitment to pubkey for withdrawals
    effective_balance: Gwei  # Balance at stake
    slashed: boolean
    # Status epochs
    activation_eligibility_epoch: Epoch  # When criteria for activation were met
    activation_epoch: Epoch
    exit_epoch: Epoch
    withdrawable_epoch: Epoch  # When validator can withdraw funds
 */
library ValidatorContainer {
    using Endian for bytes32;

    uint256 internal constant VALID_LENGTH = 8;
    uint256 internal constant MERKLE_TREE_HEIGHT = 3;

    function verifyValidatorContainerBasic(bytes32[] calldata validatorContainer) internal pure returns (bool) {
        return validatorContainer.length == VALID_LENGTH;
    }

    function getPubkey(bytes32[] calldata validatorContainer) internal pure returns (bytes32) {
        return validatorContainer[0];
    }

    function getWithdrawalCredentials(bytes32[] calldata validatorContainer) internal pure returns (bytes32) {
        return validatorContainer[1];
    }

    function getEffectiveBalance(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return validatorContainer[2].fromLittleEndianUint64();
    }

    function getSlashed(bytes32[] calldata validatorContainer) internal pure returns (bool) {
        return uint8(bytes1(validatorContainer[3])) == 1;
    }

    function getActivationEpoch(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return validatorContainer[5].fromLittleEndianUint64();
    }

    function getExitEpoch(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return validatorContainer[6].fromLittleEndianUint64();
    }

    function getWithdrawableEpoch(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return validatorContainer[7].fromLittleEndianUint64();
    }

    function merklelizeValidatorContainer(bytes32[] calldata validatorContainer) internal pure returns (bytes32) {
        bytes32[] memory leaves = validatorContainer;
        for (uint i; i < MERKLE_TREE_HEIGHT; i++) {
            bytes32[] memory roots = new bytes32[](leaves.length / 2);
            for (uint j; j < leaves.length / 2; j++) {
                roots[j] = sha256(abi.encodePacked(leaves[2 * j], leaves[2 * j + 1]));
            }
            leaves = roots;
        }

        return leaves[0];
    }
}
