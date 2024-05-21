pragma solidity ^0.8.19;

interface IBaseRestakingController {
    /// *** function signatures for staker operations ***

    /**
     * @notice Client chain users call to delegate deposited token to specific node operator.
     * @dev This assumes that the delegated assets should have already been deposited to Exocore system.
     * @param operator - The address of a registered node operator that the user wants to delegate to.
     * @param token - The address of specific token that the user wants to delegate to.
     * @param amount - The amount of @param token that the user wants to delegate to node operator.
     */
    function delegateTo(string calldata operator, address token, uint256 amount) external payable;

    function undelegateFrom(string calldata operator, address token, uint256 amount) external payable;

    /**
     * @notice Client chain users call to claim their unlocked assets from the vault.
     * @dev This function assumes that the claimable assets should have been unlocked before calling this.
     * @dev This function does not ask for grant from Exocore validator set.
     * @param token - The address of specific token that the user wants to claim from the vault.
     * @param amount - The amount of @param token that the user wants to claim from the vault.
     * @param recipient - The destination address that the assets would be transfered to.
     */
    function claim(address token, uint256 amount, address recipient) external;
}
