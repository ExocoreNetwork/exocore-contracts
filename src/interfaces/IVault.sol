pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IVault {
    function withdraw(address withdrawer, address recipient, uint256 amount) external;

    function deposit(address depositor, uint256 amount) external payable;

    function updatePrincipleBalance(address user, uint256 lastlyUpdatedPrincipleBalance) external;

    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external;

    function updateWithdrawableBalance(address user, uint256 unlockPrincipleAmount, uint256 unlockRewardAmount)
        external;

    function getUnderlyingToken() external returns (address);
}
