pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IController} from "../interfaces/IController.sol";

contract VaultStorage {
    IERC20 public underlyingToken;
    mapping(address => uint256) public principleBalances;
    mapping(address => uint256) public rewardBalances;
    mapping(address => uint256) public withdrawableBalances;

    mapping(address => uint256) public totalDepositedPrincipleAmount;
    mapping(address => uint256) public totalUnlockPrincipleAmount;

    IController public gateway;

    event PrincipleBalanceUpdated(address, uint256);
    event RewardBalanceUpdated(address, uint256);
    event WithdrawableBalanceUpdated(address, uint256, uint256);
}
