// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract RewardVaultStorage {

    // Address of the gateway contract
    address public gateway;

    // Mapping of token address to staker address to withdrawable balance
    mapping(address => mapping(address => uint256)) public withdrawableBalances;

    // Mapping of token address to AVS ID to balance
    mapping(address => mapping(address => uint256)) public totalDepositedRewards;

    // Gap for future storage variables
    uint256[40] private _gap;

    /**
     * @notice Emitted when a reward is deposited.
     * @param token The address of the token.
     * @param avs The address of the AVS.
     * @param amount The amount of the reward deposited.
     */
    event RewardDeposited(address indexed token, address indexed avs, uint256 amount);

    /**
     * @notice Emitted when a reward is unlocked.
     * @param token The address of the token.
     * @param staker The address of the staker.
     * @param amount The amount of the reward unlocked.
     */
    event RewardUnlocked(address indexed token, address indexed staker, uint256 amount);

    /**
     * @notice Emitted when a reward is withdrawn.
     * @param token The address of the token.
     * @param staker The address of the staker.
     * @param recipient The address of the recipient.
     * @param amount The amount of the reward withdrawn.
     */
    event RewardWithdrawn(address indexed token, address indexed staker, address indexed recipient, uint256 amount);

}
