// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract RewardVaultStorage {

    // Address of the gateway contract
    address public gateway;

    // Mapping of token address to staker address to withdrawable balance
    mapping(address => mapping(address => uint256)) public withdrawableBalances;

    // Mapping of token address to AVS ID to balance
    mapping(address => mapping(address => uint256)) public totalDepositedRewards;

    // Gap for future storage variables
    uint256[40] private _gap;

    event RewardDeposited(address indexed token, address indexed avs, uint256 amount);
    event RewardUnlocked(address indexed token, address indexed staker, uint256 amount);
    event RewardWithdrawn(address indexed token, address indexed staker, address indexed recipient, uint256 amount);
}
