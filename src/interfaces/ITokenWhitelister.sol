pragma solidity ^0.8.19;

interface ITokenWhitelister {
    function addWhitelistToken(address _token) external;
    function removeWhitelistToken(address _token) external;
    function addTokenVaults(address[] calldata vaults) external;

    /**
     * @dev Emitted when a new token is added to the whitelist.
     * @param _token The address of the token that has been added to the whitelist.
     */
    event WhitelistTokenAdded(address _token);

    /**
     * @dev Emitted when a token is removed from the whitelist.
     * @param _token The address of the token that has been removed from the whitelist.
     */
    event WhitelistTokenRemoved(address _token);

    /**
     * @dev Emitted when a new vault is added to the mapping of token vaults.
     * @param _vault The address of the vault that has been added.
     */
    event VaultAdded(address _vault);

    /**
     * @dev Indicates an operation failed because the specified vault already exists.
     */
    error VaultAlreadyAdded();

    /**
     * @dev Indicates an operation was attempted with a token that is not authorized.
     */
    error UnauthorizedToken();
}