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
     * @dev An array containing all the token addresses that have been added to the whitelist.
     * @notice Use this array to iterate through all whitelisted tokens.
     * This helps in operations like audits, UI display, or when removing tokens
     * from the whitelist needs an indexed approach.
     */
    address[] public whitelistTokensArray;

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
     * @dev A public array holding the Ethereum addresses of all operators that have been
     * registered in the contract. These operators, sorted by their vote power, will be
     * used to initialize the Exocore chain's validator set.
     *
     * The system used is a delegated POS system, where the vote power of each operator
     * is determined by the total amount of tokens delegated to them across all supported
     * tokens.
    */
    address[] public registeredOperators;

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
    mapping(address => mapping(string => mapping(address => uint256))) public delegations;

    /**
     * @dev Maps an operator address to a mapping, where the key is the token address and the
     * value is the amount of delegated tokens.
     * @notice This allows tracking of how much each operator has been delegated by all
     * delegators for each of the whitelisted tokens.
     */
    // delegationsByOperator means it is indexed by operator address and not that is is
    // a delegation made by the operator.
    mapping(string => mapping(address => uint256)) public delegationsByOperator;

    /**
     * @dev Maps depositor addresses to another mapping, where the key is an token address and
     * the value is the total amount of that token deposited by the depositor.
     * @notice This mapping is used to keep track of the total deposits made by each account
     * for each token.
     */
    mapping(address => mapping(address => uint256)) public totalDepositAmounts;

    /**
     * @dev Maps depositor addresses to another mapping, where the key is an token address and
     * the value is the total amount of that token deposited and free to bond by the depositor.
     * @notice Use this to check the amount available for withdrawal by each account for each
     * token.
     */
    mapping(address => mapping(address => uint256)) public withdrawableAmounts;

    /**
     * @dev List of addresses that have staked or deposited into the contract.
     * @notice This array stores all unique depositor addresses to manage and track staking
     * participation.
     */
    address[] public depositors;

    /**
     * @dev A mapping of depositor addresses to a boolean indicating whether the address has
     * deposited into the contract.
     * @notice Use this mapping to check if a specific address has deposited into the contract.
     */
    mapping(address => bool) public isDepositor;

    /**
     * @dev Stores the Layer Zero chain ID of the Exocore chain.
     * @notice Used to identify the specific Exocore chain this contract interacts with for
     * cross-chain functionalities.
     */
    uint32 public exocoreChainId;

    /**
     * @dev Address of the custom proxy admin used to manage upgradeability of this contract.
     * @notice This proxy admin facilitates the implementation switch from Bootstrap to
     * ClientChainGateway based on conditions met by the Exocore validator set's transactions.
     */
    address public customProxyAdmin;

    /**
     * @dev Address of the Client Chain Gateway logic implementation.
     * @notice This address points to the logic contract that the proxy should switch to upon
     * successful bootstrapping.
     */
    address public clientChainGatewayLogic;

    /**
     * @dev Contains the initialization data for the Client Chain Gateway logic when upgrading.
     * @notice This data is used to initialize the new logic contract (ClientChainGateway) when
     * the proxy admin switches the implementation post-bootstrapping.
     */
    bytes clientChainInitializationData;

    bool public bootstrapped;

    mapping(address => uint256) public depositsByToken;

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
     * @dev Indicates an operation failed because the specified vault already exists.
     */
    error VaultAlreadyAdded();

    /**
     * @dev Indicates an operation was attempted with a token that is not authorized.
     */
    error UnauthorizedToken();

    /**
     * @dev Indicates that an operation which is not yet supported is requested.
     */
    error NotYetSupported();

    /**
     * @dev This error is used to indicate that a received transaction originates from an
     * unexpected Layer Zero source chain.
     * @param unexpectedSrcEndpointId The source chain ID that was not expected or recognized.
     */
    error UnexpectedSourceChain(uint32 unexpectedSrcEndpointId);

    /**
     * @dev Struct to hold detailed information about a token, including its name, symbol,
     * address, decimals, total supply, and additional metadata for cross-chain operations
     * and contextual data.
     *
     * @param name The name of the token.
     * @param symbol The symbol of the token.
     * @param tokenAddress The contract address of the token.
     * @param decimals The number of decimals the token uses.
     * @param totalSupply The total supply of the token.
     * @param depositAmount The total amount of the token deposited into the contract.
     */
    struct TokenInfo {
        string name;
        string symbol;
        address tokenAddress;
        uint8 decimals;
        uint256 totalSupply;
        uint256 depositAmount;
    }

    uint256[40] private __gap;
}