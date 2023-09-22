pragma solidity ^0.8.19;

interface IController {
    event DepositResult(address indexed depositor, bool indexed success, uint256 amount);
    event WithdrawResult(address indexed withdrawer, bool indexed success, uint256 amount);
    event DelegateResult(address indexed delegator, address indexed delegatee, bool indexed success, uint256 amount);

    /// *** function signatures for staker operations ***

    /**
     * @notice Client chain users call to deposit to Exocore system for further operations like delegation, staking...
     * @dev This function should:
     * 1) lock the @param amount of @param token into vault.
     * 2) ask Exocore validator set to account for the deposited @param amount of @param token.
     * Deposited assets should remain locked until Exocore validator set responds with success or faulure. 
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
    function delegateTo(address operator, address token, uint256 amount) external;

    /**
     * @notice Client chain users call to withdraw capital from Exocore to client chain before they are granted to withdraw from the vault.
     * @dev This function should ask Exocore validator set for withdrawal grant. If Exocore validator set responds
     * with true or success, the corresponding assets should be unlocked to make them claimable by users themselves. Otherwise
     * these assets should remain locked.
     * @param token - The address of specific token that the user wants to withdraw from Exocore.
     * @param capitalAmount - capital means the assets user deposits into Exocore for delegating and staking.
     * we suppose that After deposit, its amount could only remain unchanged or decrease owing to slashing, which means that direct
     * transfer of capital is not possible.
     */
    function withdrawCapitalFromExocore(address token, uint256 capitalAmount) external;

    /**
     * @notice Client chain users call to claim their unlocked assets from the vault.
     * @dev This function assumes that the claimable assets should have been unlocked before calling this.
     * @dev This function does not ask for grant from Exocore validator set.
     * @param token - The address of specific token that the user wants to claim from the vault.
     * @param amount - The amount of @param token that the user wants to claim from the vault.
     * @param distination - The destination address that the assets would be transfered to.
     */
    function claim(address token, uint256 amount, address distination) external;

    /// *** function signatures for commands of Exocore validator set forwarded by Gateway ***

    /**
     * @notice Exocore validator set calls this through Gateway contract to grant the withdrawal from Exocore
     * to clien chain by unlocking the corresponding assets in the vault.
     * @dev Only Exocore validato set could indirectly call this function through Gateway contract. 
     * @param withdrawer - The address of specific withdrawer that Exocore validator set grants for withdrawal.
     * @param token - The address of specific token that Exocore validator set grants for withdrawal.
     * @param amount - The amount of @param token that Exocore validator set grants for withdrawal.
     */
    function grantWithdrawal(address withdrawer, address token, uint256 amount) external;
}
