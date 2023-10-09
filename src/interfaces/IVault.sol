pragma solidity ^0.8.19;

interface IVault {
    function withdraw(address recipient, uint256 amount) external payable;

    function deposit(address sender, uint256 amount) external;

    function updatePrincipleBalance(address user, uint256 principleBalance) external;

    function updateRewardBalance(address user, uint256 rewardBalance) external;

    function updateWithdrawableBalance(address user, uint256 unlockAmount) external;
}