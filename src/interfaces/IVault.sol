// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title IVault
/// @notice Interface for a Vault contract handling deposits, withdrawals, and balance updates.
/// @dev This interface defines the necessary functions for interacting with the Vault.
/// @author ExocoreNetwork
interface IVault {

    /// @notice Withdraws a specified amount from the vault.
    /// @param withdrawer The address initiating the withdrawal.
    /// @param recipient The address receiving the withdrawn amount.
    /// @param amount The amount to be withdrawn.
    function withdraw(address withdrawer, address recipient, uint256 amount) external;

    /// @notice Deposits a specified amount into the vault.
    /// @param depositor The address initiating the deposit.
    /// @param amount The amount to be deposited.
    function deposit(address depositor, uint256 amount) external payable;

    /// @notice Updates the principal balance for a user.
    /// @param user The address of the user whose principal balance is being updated.
    /// @param lastlyUpdatedPrincipalBalance The new principal balance for the user.
    function updatePrincipalBalance(address user, uint256 lastlyUpdatedPrincipalBalance) external;

    /// @notice Updates the reward balance for a user.
    /// @param user The address of the user whose reward balance is being updated.
    /// @param lastlyUpdatedRewardBalance The new reward balance for the user.
    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external;

    /// @notice Updates the withdrawable balance for a user.
    /// @param user The address of the user whose withdrawable balance is being updated.
    /// @param unlockPrincipalAmount The amount of principal to be unlocked.
    /// @param unlockRewardAmount The amount of reward to be unlocked.
    function updateWithdrawableBalance(address user, uint256 unlockPrincipalAmount, uint256 unlockRewardAmount)
        external;

    /// @notice Returns the address of the underlying token.
    /// @return The address of the underlying token.
    function getUnderlyingToken() external returns (address);

}
