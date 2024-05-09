pragma solidity ^0.8.19;

import {IBaseRestakingController} from "./IBaseRestakingController.sol";

interface ILSTRestakingController is IBaseRestakingController {
    // @notice this info is used to update specific user's owned tokens balance
    struct UserBalanceUpdateInfo {
        address user;
        uint256 updatedAt;
        TokenBalanceUpdateInfo[] tokenBalances;
    }

    struct TokenBalanceUpdateInfo {
        address token;
        uint256 lastlyUpdatedPrincipleBalance;
        uint256 lastlyUpdatedRewardBalance;
        uint256 unlockPrincipleAmount;
        uint256 unlockRewardAmount;
    }

    /// *** function signatures for staker operations ***

    /**
     * @notice Client chain users call to deposit to Exocore system for further operations like delegation, staking...
     * @dev This function should:
     * 1) lock the @param amount of @param token into vault.
     * 2) ask Exocore validator set to account for the deposited @param amount of @param token.
     * Deposit should always be considered successful on Exocore chain side.
     * @param token - The address of specific token that the user wants to deposit.
     * @param amount - The amount of @param token that the user wants to deposit.
     */
    function deposit(address token, uint256 amount) external payable;

    /**
     * @notice Client chain users call to withdraw principle from Exocore to client chain before they are granted to withdraw from the vault.
     * @dev This function should ask Exocore validator set for withdrawal grant. If Exocore validator set responds
     * with true or success, the corresponding assets should be unlocked to make them claimable by users themselves. Otherwise
     * these assets should remain locked.
     * @param token - The address of specific token that the user wants to withdraw from Exocore.
     * @param principleAmount - principle means the assets user deposits into Exocore for delegating and staking.
     * we suppose that After deposit, its amount could only remain unchanged or decrease owing to slashing, which means that direct
     * transfer of principle is not possible.
     */
    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external payable;

    function withdrawRewardFromExocore(address token, uint256 rewardAmount) external payable;
}
