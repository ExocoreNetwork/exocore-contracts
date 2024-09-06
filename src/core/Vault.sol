// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {IVault} from "../interfaces/IVault.sol";
import {VaultStorage} from "../storage/VaultStorage.sol";

import {Errors} from "../libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title Vault
/// @author ExocoreNetwork
/// @notice Implementation of IVault, used to store user tokens. Each Vault is unique to an
/// underlying token and is controlled by a gateway.
contract Vault is Initializable, VaultStorage, IVault {

    using SafeERC20 for IERC20;

    /// @dev Allows only the gateway to call the function.
    modifier onlyGateway() {
        if (msg.sender != address(gateway)) {
            revert Errors.VaultCallerIsNotGateway();
        }
        _;
    }

    /// @dev This constructor disables initialization so that the proxy pattern can be used.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the Vault contract.
    /// @param underlyingToken_ The address of the underlying token.
    /// @param tvlLimit_ The TVL limit for the vault.
    /// @param gateway_ The address of the gateway contract.
    /// @dev Vault only works with normal ERC20 like reward-bearing LST tokens like wstETH, rETH.
    /// And It is not intended to be used for: 1) rebasing token like stETH, since we assume staker's
    /// balance would not change if nothing is done after deposit, 2) fee-on-transfer token, since we
    /// assume Vault would account for the amount that staker transfers to it.
    function initialize(address underlyingToken_, uint256 tvlLimit_, address gateway_) external initializer {
        if (underlyingToken_ == address(0) || gateway_ == address(0)) {
            revert Errors.ZeroAddress();
        }

        underlyingToken = IERC20(underlyingToken_);
        tvlLimit = tvlLimit_;
        gateway = ILSTRestakingController(gateway_);
        consumedTvl = 0;
    }

    /// @inheritdoc IVault
    function getUnderlyingToken() public view returns (address) {
        return address(underlyingToken);
    }

    /// @notice Gets the withdrawable balance of a user.
    /// @param withdrawer Address of the user who wants to withdraw tokens.
    function getWithdrawableBalance(address withdrawer) external view returns (uint256 balance) {
        return withdrawableBalances[withdrawer];
    }

    /// @inheritdoc IVault
    function withdraw(address withdrawer, address recipient, uint256 amount) external onlyGateway {
        if (amount > withdrawableBalances[withdrawer]) {
            revert Errors.VaultWithdrawalAmountExceeds();
        }
        if (amount > consumedTvl) {
            revert Errors.VaultTvlLimitExceeded();
        }

        withdrawableBalances[withdrawer] -= amount;
        consumedTvl -= amount;
        underlyingToken.safeTransfer(recipient, amount);

        emit WithdrawalSuccess(withdrawer, recipient, amount);
    }

    /// @inheritdoc IVault
    // Though `safeTransferFrom` has arbitrary passed in `depositor` as sender, this function is only callable by
    // `gateway` and `gateway` would make sure only the `msg.sender` would be the depositor.
    // slither-disable-next-line arbitrary-send-erc20
    function deposit(address depositor, uint256 amount) external payable onlyGateway {
        underlyingToken.safeTransferFrom(depositor, address(this), amount);
        totalDepositedPrincipalAmount[depositor] += amount;
        consumedTvl += amount;
        if (consumedTvl > tvlLimit) {
            // The TVL limit for a token can only be consumed (or freed) if
            // (1) there is a deposit or a withdrawal
            // (2) the token is slashed. but we don't account for that here since that is a
            // small proportion, and, the tvl limit is only for risk management.
            revert Errors.VaultTvlLimitExceeded();
        }
    }

    /// @inheritdoc IVault
    function updatePrincipalBalance(address user, uint256 lastlyUpdatedPrincipalBalance) external onlyGateway {
        principalBalances[user] = lastlyUpdatedPrincipalBalance;

        emit PrincipalBalanceUpdated(user, lastlyUpdatedPrincipalBalance);
    }

    /// @inheritdoc IVault
    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external onlyGateway {
        rewardBalances[user] = lastlyUpdatedRewardBalance;

        emit RewardBalanceUpdated(user, lastlyUpdatedRewardBalance);
    }

    /// @inheritdoc IVault
    function updateWithdrawableBalance(address user, uint256 unlockPrincipalAmount, uint256 unlockRewardAmount)
        external
        onlyGateway
    {
        uint256 totalDeposited = totalDepositedPrincipalAmount[user];
        if (unlockPrincipalAmount > totalDeposited) {
            revert Errors.VaultPrincipalExceedsTotalDeposit();
        }

        totalUnlockPrincipalAmount[user] += unlockPrincipalAmount;
        if (totalUnlockPrincipalAmount[user] > totalDeposited) {
            revert Errors.VaultTotalUnlockPrincipalExceedsDeposit();
        }

        withdrawableBalances[user] = withdrawableBalances[user] + unlockPrincipalAmount + unlockRewardAmount;

        emit WithdrawableBalanceUpdated(user, unlockPrincipalAmount, unlockRewardAmount);
    }

    /// @inheritdoc IVault
    function setTvlLimit(uint256 tvlLimit_) external onlyGateway {
        tvlLimit = tvlLimit_;
        emit TvlLimitUpdated(tvlLimit);
    }

    /// @inheritdoc IVault
    function getTvlLimit() external view returns (uint256) {
        return tvlLimit;
    }

    /// @inheritdoc IVault
    function getConsumedTvl() external view returns (uint256) {
        return consumedTvl;
    }

}
