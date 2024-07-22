// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title IBaseRestakingController
/// @author ExocoreNetwork
/// @notice The IBaseRestakingController interface provides a set of functions for staker operations.
interface IBaseRestakingController {

    /// @notice Delegates a specified amount of tokens to a given operator.
    /// @param operator The address of the operator to delegate tokens to.
    /// @param token The address of the token to be delegated.
    /// @param amount The amount of tokens to delegate.
    function delegateTo(string calldata operator, address token, uint256 amount) external payable;

    /// @notice Undelegates a specified amount of tokens from a given operator.
    /// @param operator The address of the operator to undelegate tokens from.
    /// @param token The address of the token to be undelegated.
    /// @param amount The amount of tokens to undelegate.
    function undelegateFrom(string calldata operator, address token, uint256 amount) external payable;

    /// @notice Client chain users call to claim their unlocked assets from the vault.
    /// @dev This function assumes that the claimable assets should have been unlocked before calling this.
    /// @dev This function does not ask for grant from Exocore validator set.
    /// @param token The address of specific token that the user wants to claim from the vault.
    /// @param amount The amount of @param token that the user wants to claim from the vault.
    /// @param recipient The destination address that the assets would be transfered to.
    function claim(address token, uint256 amount, address recipient) external;

}
