pragma solidity ^0.8.19;

interface IVault {

    function withdraw(address withdrawer, address recipient, uint256 amount) external;

    function deposit(address depositor, uint256 amount) external payable;

    function updatePrincipalBalance(address user, uint256 lastlyUpdatedPrincipalBalance) external;

    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external;

    function updateWithdrawableBalance(address user, uint256 unlockPrincipalAmount, uint256 unlockRewardAmount)
        external;

    function getUnderlyingToken() external returns (address);

}
