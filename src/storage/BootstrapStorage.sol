pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";
import {GatewayStorage} from "./GatewayStorage.sol";

// BootstrapStorage should inherit from GatewayStorage since it exists
// prior to ClientChainGateway. ClientChainGateway should inherit from
// BootstrapStorage to ensure overlap of positioning between the
// members of each contract.
contract BootstrapStorage is GatewayStorage {
    /**
     * @notice A timestamp representing the scheduled spawn time of the Exocore chain, which
     * influences the contract's operational restrictions.
     *
     * @dev This variable sets a specific point in time (in UNIX timestamp format) that triggers
     * a freeze period for the contract 24 hours before the Exocore chain is expected to launch.
     * Operations that could alter the state of the contract significantly are not allowed
     * during this freeze period to ensure stability and integrity leading up to the spawn time.
     */
    uint256 public exocoreSpawnTime;

    /**
     * @notice The amount of time before the Exocore spawn time during which operations are
     * restricted.
     *
     * @dev This variable defines a period in seconds before the scheduled spawn time of the
     * Exocore chain, during which certain contract operations are locked to prevent state
     * changes. The lock period is intended to ensure stability and integrity of the contract
     * state leading up to the critical event. This period can be customized at the time of
     * contract deployment according to operational needs and security considerations.
     */
    uint256 public offsetTime;

    /**
     * @dev Stores a mapping of whitelisted token addresses to their status.
     * @notice Use this to check if a token is allowed for processing.
     * Each token address maps to a boolean indicating whether it is whitelisted.
     */
    mapping(address => bool) public whitelistTokens;

    /**
     * @dev Maps token addresses to their corresponding vault contracts.
     * @notice Access the vault interface for a specific token using this mapping.
     * Each token address maps to an IVault contract instance handling its operations.
     */
    mapping(address => IVault) public tokenVaults;

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
     * @dev Indicates an operation failed because the specified vault does not exist.
     */
    error VaultNotExist();

    /**
     * @dev Indicates an operation was attempted with a token that is not authorized.
     */
    error UnauthorizedToken();


    uint256[40] private __gap;
}