pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";

contract VaultStorage {
    mapping(address => uint256) public principleBalances;
    mapping(address => uint256) public rewardBalances;
    mapping(address => uint256) public withdrawableBalances;

    mapping(address => uint256) public totalDepositedPrincipleAmount;
    mapping(address => uint256) public totalUnlockPrincipleAmount;

    IERC20 public underlyingToken;
    ILSTRestakingController public gateway;

    event PrincipleBalanceUpdated(address, uint256);
    event RewardBalanceUpdated(address, uint256);
    event WithdrawableBalanceUpdated(address, uint256, uint256);
    event WithdrawalSuccess(address, address, uint256);
}
