// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Errors} from "../libraries/Errors.sol";
import {RewardVaultStorage} from "../storage/RewardVaultStorage.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IRewardVault} from "../interfaces/IRewardVault.sol";

contract RewardVault is RewardVaultStorage, Initializable, IRewardVault {

    using SafeERC20 for IERC20;

    modifier onlyGateway() {
        if (msg.sender != gateway) {
            revert Errors.VaultCallerIsNotGateway();
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address gateway_) public initializer {
        gateway = gateway_;
    }

    function deposit(address token, address avs, uint256 amount) external onlyGateway {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        totalDepositedRewards[token][avs] += amount;
    }

    function withdraw(address token, address withdrawer, address recipient, uint256 amount) external onlyGateway {
        if (withdrawableBalances[token][withdrawer] < amount) {
            revert Errors.InsufficientBalance();
        }
        withdrawableBalances[token][withdrawer] -= amount;
        IERC20(token).safeTransfer(recipient, amount);
    }

    function unlockReward(address token, address withdrawer, uint256 amount)
        external
        onlyGateway
    {
        withdrawableBalances[token][withdrawer] += amount;

        emit RewardUnlocked(token, withdrawer, amount);
    }

    function getWithdrawableBalance(address token, address withdrawer) external view returns (uint256) {
        return withdrawableBalances[token][withdrawer];
    }

    function getTotalDepositedRewards(address token, address avs) external view returns (uint256) {
        return totalDepositedRewards[token][avs];
    }
}
