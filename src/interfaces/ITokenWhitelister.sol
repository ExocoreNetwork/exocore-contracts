// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title ITokenWhitelister
/// @author ExocoreNetwork
/// @notice An interface for the TokenWhitelister contract that allows whitelisting and obtaining
/// the count of whitelisted tokens.
interface ITokenWhitelister {

    /// @notice Adds a list of whitelisted tokens.
    /// @param tokens The list of token addresses to be whitelisted.
    /// @param tvlLimits The list of TVL limits for the corresponding tokens.
    function addWhitelistTokens(address[] calldata tokens, uint256[] calldata tvlLimits) external;

    /// @notice Gets the count of whitelisted tokens.
    /// @return The count of whitelisted tokens.
    function getWhitelistedTokensCount() external returns (uint256);

    /// @notice Updates the TVL limits for a list of tokens.
    /// @dev The tokens must be whitelisted before.
    /// @param tokens The list of token addresses.
    /// @param tvlLimits The list of corresponding TVL limits.
    function updateTvlLimits(address[] calldata tokens, uint256[] calldata tvlLimits) external;

}
