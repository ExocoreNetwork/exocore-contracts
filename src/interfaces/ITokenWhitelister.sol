// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title ITokenWhitelister
/// @author ExocoreNetwork
/// @notice An interface for the TokenWhitelister contract that allows whitelisting and obtaining
/// the count of whitelisted tokens.
interface ITokenWhitelister {

    /// @notice Adds a list of whitelisted tokens.
    /// @param tokens The list of token addresses to be whitelisted.
    function addWhitelistTokens(address[] calldata tokens) external;

    /// @notice Gets the count of whitelisted tokens.
    /// @return The count of whitelisted tokens.
    function getWhitelistedTokensCount() external returns (uint256);

}
