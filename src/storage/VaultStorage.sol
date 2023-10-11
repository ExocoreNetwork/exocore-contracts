pragma solidity ^0.8.19;

contract VaultStorage {
    address public underlyingToken;
    mapping(address => uint256) public principleBalances;
    mapping(address => uint256) public rewardBalances;
    mapping(address => uint256) public withdrawableBalances;

    mapping(address => uint256) public totalDepositedPrincipleAmount;
    mapping(address => uint256) public totalUnlockPrincipleAmount;

    address public controller;
}