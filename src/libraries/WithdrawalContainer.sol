pragma solidity ^0.8.19;

import "../libraries/Endian.sol";

/**
 * class Withdrawal(Container):
    index: WithdrawalIndex
    validator_index: ValidatorIndex
    address: ExecutionAddress
    amount: Gwei
 */
library WithdrawalContainer {
    using Endian for bytes32;

    uint256 internal constant VALID_LENGTH = 4;
    uint256 internal constant MERKLE_TREE_HEIGHT = 2;
    function verifyWithdrawalContainerBasic(bytes32[] calldata withdrawalContainer) internal pure returns (bool) {
        return withdrawalContainer.length == VALID_LENGTH;
    }

    function getWithdrawalIndex(bytes32[] calldata withdrawalContainer) internal pure returns (uint64) {
        return withdrawalContainer[0].fromLittleEndianUint64();
    }

    function getValidatorIndex(bytes32[] calldata withdrawalContainer) internal pure returns (uint64) {
        return withdrawalContainer[1].fromLittleEndianUint64();
    }

    function getExecutionAddress(bytes32[] calldata withdrawalContainer) internal pure returns (address) {
        return address(bytes20(withdrawalContainer[2]));
    }

    /**
     * @dev Retrieves a withdrawal's withdrawal amount (in gwei)
     */
    function getAmount(bytes32[] calldata withdrawalContainer) internal pure returns (uint64) {
        return withdrawalContainer[3].fromLittleEndianUint64();
    }

    function merklelizeWithdrawalContainer(bytes32[] calldata withdrawalContainer) internal pure returns (bytes32) {
        bytes32[] memory leaves = withdrawalContainer;
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
