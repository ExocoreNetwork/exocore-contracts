// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library ExocoreBytes {

    /// @notice Converts an Ethereum address to Exocore's 32-byte address format
    /// @param addr The Ethereum address to convert
    /// @return The address as 32-byte Exocore format (20 bytes + right padding)
    function toExocoreBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }

}
