// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title VaultStorage
/// @author ExocoreNetwork
/// @notice Storage contract for the Vault contract.
contract VaultStorage {

    /// @notice Mapping of principal balances for each user.
    mapping(address => uint256) public principalBalances;

    /// @notice Mapping of reward balances for each user.
    mapping(address => uint256) public rewardBalances;

    /// @notice Mapping of withdrawable balances for each user.
    mapping(address => uint256) public withdrawableBalances;

    /// @notice Mapping of total deposited principal amounts for each user.
    mapping(address => uint256) public totalDepositedPrincipalAmount;

    /// @notice Mapping of total unlocked principal amounts for each user.
    mapping(address => uint256) public totalUnlockPrincipalAmount;

    /// @notice Address of the underlying token.
    IERC20 public underlyingToken;

    /// @notice TVL limit for the vault.
    uint256 public tvlLimit;

    /// @notice Consumed TVL.
    uint256 public consumedTvl;

    /// @notice Address of the gateway contract.
    ILSTRestakingController public gateway;

    /// @notice Emitted when a user's principal balance is updated.
    /// @param user The address of the user.
    /// @param amount The new principal balance.
    event PrincipalBalanceUpdated(address user, uint256 amount);

    /// @notice Emitted when a user's reward balance is updated.
    /// @param user The address of the user.
    /// @param amount The new reward balance.
    event RewardBalanceUpdated(address user, uint256 amount);

    /// @notice Emmitted when a user's withdrawable balance is updated.
    /// @param user The address of the user.
    /// @param pAmount The new principal balance.
    /// @param rAmount The new reward balance.
    event WithdrawableBalanceUpdated(address user, uint256 pAmount, uint256 rAmount);

    /// @notice Emitted upon withdrawal success.
    /// @param src The address of the withdrawer.
    /// @param dst The address of the recipient.
    /// @param amount The amount withdrawn.
    event WithdrawalSuccess(address src, address dst, uint256 amount);

    /// @notice Emitted upon the TVL limit being updated.
    /// @param newTvlLimit The new TVL limit.
    event TvlLimitUpdated(uint256 newTvlLimit);

    /// @dev Storage gap to allow for future upgrades.
    uint256[40] private __gap;

}
