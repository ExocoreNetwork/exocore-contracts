pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";

import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {IVault} from "../interfaces/IVault.sol";

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
     * @dev Maps Ethereum addresses to their corresponding Exocore addresses.
     * @notice This mapping is used to track which Ethereum address is linked to which
     * Exocore address.
     * Useful for verifying if a particular Ethereum address has already registered an operator.
     */
    mapping(address => string) public ethToExocoreAddress;

    /**
     * @dev Maps Exocore addresses to their corresponding operator details stored in an 
     * Operator` struct.
     * @notice Use this mapping to access or modify operator details associated with a specific
     * Exocore address.
     * This helps in managing and accessing all registered operator data efficiently.
     */
    mapping(string => IOperatorRegistry.Operator) public operators;

    /**
     * @dev A public array holding the Exocore addresses of all operators that have been
     * registered in the contract. These operators, sorted by their vote power, will be
     * used to initialize the Exocore chain's validator set.
     *
     * The system used is a delegated POS system, where the vote power of each operator
     * is determined by the total amount of tokens delegated to them across all supported
     * tokens.
    */
    string[] public registeredOperators;

    /**
     * @dev A mapping of operator Exocore address to a boolean indicating whether said operator
     * has edited their commission rate.
     *
     * This mapping is used to enforce a once-only commission rate change for operators before
     * the chain bootstrap.
     */
    mapping(string => bool) public commissionEdited;

    /**
     * @dev Maps a delegator address to a nested mapping, where the first key the operator
     * address and the second key is the token's address, pointing to the amount of tokens
     * delegated.
     * @notice This allows tracking of how much each delegator has delegated to each operator
     * for all of the whitelisted tokens.
     */
    mapping(address => mapping(string => mapping(address => uint256))) delegations;

    /**
     * @dev Maps depositor addresses to another mapping, where the key is an token address and
     * the value is the total amount of that token deposited by the depositor.
     * @notice This mapping is used to keep track of the total deposits made by each account
     * for each token.
     */
    mapping(address => mapping(address => uint256)) totalDepositAmounts;

    /**
     * @dev Maps depositor addresses to another mapping, where the key is an token address and
     * the value is the total amount of that token deposited and free to bond by the depositor.
     * @notice Use this to check the amount available for withdrawal by each account for each
     * token.
     */
    mapping(address => mapping(address => uint256)) withdrawableAmounts;

    /**
     * @notice Emitted when the spawn time of the Exocore chain is updated.
     *
     * @dev This event is triggered whenever the contract owner updates the spawn time of the
     * Exocore chain.
     *
     * @param newSpawnTime The new time (in seconds) that has been set.
     */
    event SpawnTimeUpdated(uint256 newSpawnTime);

    /**
     * @notice Emitted when the offset time before the Exocore spawn time, during which
     * operations are restricted, is updated.
     *
     * @dev This event is triggered whenever the contract owner updates the offset time that
     * defines the operational lock period leading up to the Exocore chain's launch. The
     * offset time determines how long before the spawn time the contract will restrict certain
     * operations to ensure stability and integrity. This event logs the new offset time for
     * transparency and traceability.
     *
     * @param newOffsetTime The new offset time (in seconds) that has been set. This value
     * represents the duration before the Exocore spawn time during which certain contract
     * operations are locked.
     */
    event OffsetTimeUpdated(uint256 newOffsetTime);

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
     * @dev Emitted when a new operator is registered in the contract.
     * @param ethAddress The Ethereum address of the operator.
     * @param operatorExocoreAddress The Exocore address of the operator.
     * @param name The human-readable name of the operator.
     * @param commission The commission details for the operator.
     * @param consensusPublicKey The public key used for consensus operations.
     */
    event OperatorRegistered(
        address ethAddress,
        string operatorExocoreAddress,
        string name,
        IOperatorRegistry.Commission commission,
        bytes32 consensusPublicKey
    );

    /**
     * @dev Emitted when an operator's consensus key is updated.
     * @param operatorExocoreAddress The Exocore address of the operator.
     * @param newConsensusPublicKey The new consensus key for the operator.
     */
    event OperatorKeyReplaced(
        string operatorExocoreAddress,
        bytes32 newConsensusPublicKey
    );

    /**
     * @dev Indicates an operation failed because the specified vault does not exist.
     */
    error VaultNotExist();

    /**
     * @dev Indicates an operation was attempted with a token that is not authorized.
     */
    error UnauthorizedToken();

    /**
     * @dev Indicates that an operation which is not yet supported is requested.
     */
    error NotYetSupported();


    uint256[40] private __gap;
}