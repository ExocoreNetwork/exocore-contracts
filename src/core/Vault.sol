pragma solidity ^0.8.19;

import {VaultStorage} from "../storage/VaultStorage.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract Vault is Initializable, VaultStorage, IVault {
    using SafeERC20 for IERC20;

    modifier onlyController() {
        require(msg.sender == controller, "only callable for controller");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _underlyingToken, address _controller) external initializer {
        underlyingToken = _underlyingToken;
        controller = _controller;
    }

    function withdraw(address depositor, uint256 amount) external onlyController {
        require(amount <= withdrawableBalances[depositor], "can not withdraw more amount than depositor's withdrawable balance");
        
        IERC20(underlyingToken).safeTransfer(depositor, amount);
    }

    function deposit(address depositor, uint256 amount) external payable onlyController {
        IERC20(underlyingToken).safeTransferFrom(depositor, address(this), amount);
        totalDepositedPrincipleAmount[depositor] += amount;
    }

    function updatePrincipleBalance(address user, uint256 lastlyUpdatedPrincipleBalance) external onlyController {
        principleBalances[user] = lastlyUpdatedPrincipleBalance;
    }

    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external onlyController {
        rewardBalances[user] = lastlyUpdatedRewardBalance;
    }

    function updateWithdrawableBalance(address user, uint256 unlockPrincipleAmount, uint256 unlockRewardAmount) external onlyController {
        require(unlockPrincipleAmount <= totalDepositedPrincipleAmount[user], "cannot unlock a principal amount larger than the total deposited");

        totalUnlockPrincipleAmount[user] += unlockPrincipleAmount;
        require(totalUnlockPrincipleAmount[user] <= totalDepositedPrincipleAmount[user], "total unlocked principle amount cannot be larger than the total deposited");

        withdrawableBalances[user] = withdrawableBalances[user] + unlockPrincipleAmount + unlockRewardAmount;
    }
}