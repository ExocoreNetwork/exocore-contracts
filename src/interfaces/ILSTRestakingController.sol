pragma solidity ^0.8.19;

interface ILSTRestakingController {
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
     * @notice Client chain users call to delegate deposited token to specific node operator.
     * @dev This assumes that the delegated assets should have already been deposited to Exocore system.
     * @param operator - The address of a registered node operator that the user wants to delegate to.
     * @param token - The address of specific token that the user wants to delegate to.
     * @param amount - The amount of @param token that the user wants to delegate to node operator.
     */
    function delegateTo(string calldata operator, address token, uint256 amount) external payable;

    function undelegateFrom(string calldata, address token, uint256 amount) external payable;

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

    /**
     * @notice Client chain users call to claim their unlocked assets from the vault.
     * @dev This function assumes that the claimable assets should have been unlocked before calling this.
     * @dev This function does not ask for grant from Exocore validator set.
     * @param token - The address of specific token that the user wants to claim from the vault.
     * @param amount - The amount of @param token that the user wants to claim from the vault.
     * @param recipient - The destination address that the assets would be transfered to.
     */
    function claim(address token, uint256 amount, address recipient) external;

    /// *** function signatures for commands of Exocore validator set forwarded by Gateway ***

    /**
     * @notice This should only be called by Exocore validator set through Gateway to update user's involved
     * lastly updated token balance.
     * @dev Only Exocore validato set could indirectly call this function through Gateway contract.
     * @dev This function could be called in two scenaries:
     * 1) Exocore validator set periodically calls this to update user principle and reward balance.
     * 2) Exocore validator set sends reponse for the request of withdrawPrincipleFromExocore and unlock part of
     * the vault assets and update user's withdrawable balance correspondingly.
     * @param info - The info needed for updating users balance.
     */
    function updateUsersBalances(UserBalanceUpdateInfo[] calldata info) external;
}
