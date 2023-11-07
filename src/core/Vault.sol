pragma solidity ^0.8.19;

import {VaultStorage} from "../storage/VaultStorage.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {IGateway} from "../interfaces/IGateway.sol";

contract Vault is Initializable, VaultStorage, IVault {
    using SafeERC20 for IERC20;

    modifier onlyGateway() {
        require(msg.sender == address(gateway), "only callable for controller");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function getUnderlyingToken() public view returns(address) {
        return address(underlyingToken);
    }

    function getWithdrawableBalance(address withdrawer) external view returns(uint256 balance) {
        return withdrawableBalances[withdrawer];
    }

    function initialize(address _underlyingToken, address _gateway) external initializer {
        underlyingToken = IERC20(_underlyingToken);
        gateway = IGateway(_gateway);
    }

    function withdraw(address withdrawer, address recipient, uint256 amount) external onlyGateway {
        require(amount <= withdrawableBalances[withdrawer], "can not withdraw more amount than depositor's withdrawable balance");
        
        withdrawableBalances[withdrawer] -= amount;
        underlyingToken.safeTransfer(recipient, amount);
    }

    function deposit(address depositor, uint256 amount) external payable onlyGateway {
        underlyingToken.safeTransferFrom(depositor, address(this), amount);
        totalDepositedPrincipleAmount[depositor] += amount;
    }

    function updatePrincipleBalance(address user, uint256 lastlyUpdatedPrincipleBalance) external onlyGateway {
        principleBalances[user] = lastlyUpdatedPrincipleBalance;
    }

    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external onlyGateway {
        rewardBalances[user] = lastlyUpdatedRewardBalance;
    }

    function updateWithdrawableBalance(address user, uint256 unlockPrincipleAmount, uint256 unlockRewardAmount) external onlyGateway {
        require(unlockPrincipleAmount <= totalDepositedPrincipleAmount[user], "cannot unlock a principal amount larger than the total deposited");

        totalUnlockPrincipleAmount[user] += unlockPrincipleAmount;
        require(totalUnlockPrincipleAmount[user] <= totalDepositedPrincipleAmount[user], "total unlocked principle amount cannot be larger than the total deposited");

        withdrawableBalances[user] = withdrawableBalances[user] + unlockPrincipleAmount + unlockRewardAmount;
    }
}