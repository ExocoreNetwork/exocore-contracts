pragma solidity ^0.8.19;

import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {IVault} from "../interfaces/IVault.sol";
import {VaultStorage} from "../storage/VaultStorage.sol";

import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {Errors} from "../libraries/Errors.sol";

contract Vault is Initializable, VaultStorage, IVault {

    using SafeERC20 for IERC20;

    modifier onlyGateway() {
        if (msg.sender != address(gateway)) {
            revert Errors.VaultCallerIsNotGateway();
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address underlyingToken_, address gateway_) external initializer {
        if (underlyingToken_ == address(0)) {
            revert Errors.ZeroAddress();
        }
        if (gateway_ == address(0)) {
            revert Errors.ZeroAddress();
        }

        underlyingToken = IERC20(underlyingToken_);
        gateway = ILSTRestakingController(gateway_);
    }

    function getUnderlyingToken() public view returns (address) {
        return address(underlyingToken);
    }

    function getWithdrawableBalance(address withdrawer) external view returns (uint256 balance) {
        return withdrawableBalances[withdrawer];
    }

    function withdraw(address withdrawer, address recipient, uint256 amount) external onlyGateway {
        if (amount > withdrawableBalances[withdrawer]) {
            revert Errors.VaultWithdrawalAmountExceeds();
        }

        withdrawableBalances[withdrawer] -= amount;
        underlyingToken.safeTransfer(recipient, amount);

        emit WithdrawalSuccess(withdrawer, recipient, amount);
    }

    function deposit(address depositor, uint256 amount) external payable onlyGateway {
        underlyingToken.safeTransferFrom(depositor, address(this), amount);
        totalDepositedPrincipalAmount[depositor] += amount;
    }

    function updatePrincipalBalance(address user, uint256 lastlyUpdatedPrincipalBalance) external onlyGateway {
        principalBalances[user] = lastlyUpdatedPrincipalBalance;

        emit PrincipalBalanceUpdated(user, lastlyUpdatedPrincipalBalance);
    }

    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external onlyGateway {
        rewardBalances[user] = lastlyUpdatedRewardBalance;

        emit RewardBalanceUpdated(user, lastlyUpdatedRewardBalance);
    }

    function updateWithdrawableBalance(address user, uint256 unlockPrincipalAmount, uint256 unlockRewardAmount)
        external
        onlyGateway
    {
        uint256 totalDeposited = totalDepositedPrincipalAmount[user];

        totalUnlockPrincipalAmount[user] += unlockPrincipalAmount;
        if (totalUnlockPrincipalAmount[user] > totalDeposited) {
            revert Errors.VaultTotalUnlockPrincipalExceedsDeposit();
        }

        withdrawableBalances[user] = withdrawableBalances[user] + unlockPrincipalAmount + unlockRewardAmount;

        emit WithdrawableBalanceUpdated(user, unlockPrincipalAmount, unlockRewardAmount);
    }

}
