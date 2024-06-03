pragma solidity ^0.8.19;

interface ITokenWhitelister {
    function addWhitelistToken(address _token) external;
    function removeWhitelistToken(address _token) external;

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
     * @dev Indicates an operation was attempted with a token that is not authorized.
     */
    error UnauthorizedToken();
}
