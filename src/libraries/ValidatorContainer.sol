pragma solidity ^0.8.19;

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
    uint256 internal constant VALID_LENGTH = 8;
    uint256 internal constant MERKLE_TREE_HEIGHT = 3;
    
    function verifyBasic(bytes32[] calldata validatorContainer) internal pure returns (bool) {
        return validatorContainer.length == VALID_LENGTH;
    }

    function getPubkey(bytes32[] calldata validatorContainer) internal pure returns (bytes32) {
        return validatorContainer[0];
    }

    function getWithdrawalCredentials(bytes32[] calldata validatorContainer) internal pure returns (bytes32) {
        return validatorContainer[1];
    }

    function getEffectiveBalance(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return uint64(bytes8(validatorContainer[2]));
    }

    function getSlashed(bytes32[] calldata validatorContainer) internal pure returns (bool) {
        return uint8(bytes1(validatorContainer[3])) == 1;
    }

    function getActivationEpoch(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return uint64(bytes8(validatorContainer[5]));
    }

    function getExitEpoch(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return uint64(bytes8(validatorContainer[6]));
    }

    function getWithdrawableEpoch(bytes32[] calldata validatorContainer) internal pure returns (uint64) {
        return uint64(bytes8(validatorContainer[7]));
    }

    function merklelize(bytes32[] calldata validatorContainer) internal pure returns (bytes32) {
        bytes32[] memory leaves = validatorContainer;
        for (uint i; i < MERKLE_TREE_HEIGHT; i++) {
            bytes32[] memory roots = new bytes32[](leaves.length / 2);
            for (uint j; j < leaves.length / 2; j++) {
                roots[i] = sha256(abi.encodePacked(leaves[2 * i], leaves[2 * i + 1]));
            }
            leaves = roots;
        }

        return leaves[0];
    }
}