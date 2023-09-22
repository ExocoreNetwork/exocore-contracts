pragma solidity ^0.8.19;

interface IVault {
    struct UserBalance {
        address user;
        uint256 ExocoreCapitalBalance;
        uint256 withdrawAmount;
    }

    function claim(address recipient, uint256 amount) external payable;

    function deposit(address sender, uint256 amount) external;

    function refreshUserBalance(address user, UserBalance calldata balance) external;
}