pragma solidity ^0.8.19;

import {VaultStorage} from "../storage/VaultStorage.sol";
import {IVault} from "../interfaces/IVault.sol";
import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";

import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";

contract Vault is Initializable, VaultStorage, IVault {
    using SafeERC20 for IERC20;

    modifier onlyGateway() {
        require(msg.sender == address(gateway), "Vault: caller is not the gateway");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address underlyingToken_, address gateway_) external initializer {
        require(underlyingToken_ != address(0), "Vault: underlying token can not be empty");
        require(gateway_ != address(0), "VaultStorage: the gateway address should not be empty");

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
        require(
            amount <= withdrawableBalances[withdrawer],
            "Vault: withdrawal amount is larger than depositor's withdrawable balance"
        );

        withdrawableBalances[withdrawer] -= amount;
        underlyingToken.safeTransfer(recipient, amount);

        emit WithdrawalSuccess(withdrawer, recipient, amount);
    }

    function deposit(address depositor, uint256 amount) external payable onlyGateway {
        underlyingToken.safeTransferFrom(depositor, address(this), amount);
        totalDepositedPrincipleAmount[depositor] += amount;
    }

    function updatePrincipleBalance(address user, uint256 lastlyUpdatedPrincipleBalance) external onlyGateway {
        principleBalances[user] = lastlyUpdatedPrincipleBalance;

        emit PrincipleBalanceUpdated(user, lastlyUpdatedPrincipleBalance);
    }

    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external onlyGateway {
        rewardBalances[user] = lastlyUpdatedRewardBalance;

        emit RewardBalanceUpdated(user, lastlyUpdatedRewardBalance);
    }

    function updateWithdrawableBalance(
        address user,
        uint256 unlockPrincipleAmount,
        uint256 unlockRewardAmount
    ) external onlyGateway {
        uint256 totalDeposited = totalDepositedPrincipleAmount[user];
        require(
            unlockPrincipleAmount <= totalDeposited,
            "Vault: principle unlock amount is larger than the total deposited amount"
        );

        totalUnlockPrincipleAmount[user] += unlockPrincipleAmount;
        require(
            totalUnlockPrincipleAmount[user] <= totalDeposited,
            "Vault: total principle unlock amount is larger than the total deposited amount"
        );

        withdrawableBalances[user] = withdrawableBalances[user] + unlockPrincipleAmount + unlockRewardAmount;

        emit WithdrawableBalanceUpdated(user, unlockPrincipleAmount, unlockRewardAmount);
    }
}
