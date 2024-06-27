pragma solidity ^0.8.19;

import {BeaconProxyBytecode} from "../core/BeaconProxyBytecode.sol";
import {Vault} from "../core/Vault.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";

import {IVault} from "../interfaces/IVault.sol";
import {GatewayStorage} from "./GatewayStorage.sol";
import {IBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

// BootstrapStorage should inherit from GatewayStorage since it exists
// prior to ClientChainGateway. ClientChainStorage should inherit from
// BootstrapStorage to ensure overlap of positioning between the
// members of each contract.
contract BootstrapStorage is GatewayStorage {

    /* -------------------------------------------------------------------------- */
    /*               state variables exclusively owned by Bootstrap               */
    /* -------------------------------------------------------------------------- */

    // time and duration
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
    uint256 public offsetDuration;

    // total deposits of said tokens
    /**
     * @dev A mapping of token addresses to the total amount of that token deposited into the
     * contract.
     * @notice This mapping is used to track the deposits made by all depositors for each token.
     */
    mapping(address tokenAddress => uint256 amount) public depositsByToken;

    // operator information, including delegations received by them
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
     * @dev Maps Ethereum addresses to their corresponding Exocore addresses.
     * @notice This mapping is used to track which Ethereum address is linked to which
     * Exocore address.
     * Useful for verifying if a particular Ethereum address has already registered an operator.
     */
    mapping(address ethAddress => string exoAddress) public ethToExocoreAddress;

    /**
     * @dev Maps Exocore addresses to their corresponding operator details stored in an
     * Operator` struct.
     * @notice Use this mapping to access or modify operator details associated with a specific
     * Exocore address.
     * This helps in managing and accessing all registered operator data efficiently.
     */
    mapping(string exoAddress => IOperatorRegistry.Operator operator) public operators;

    /**
     * @dev A mapping of operator Exocore address to a boolean indicating whether said operator
     * has edited their commission rate.
     *
     * This mapping is used to enforce a once-only commission rate change for operators before
     * the chain bootstrap.
     */
    mapping(string exoAddress => bool hasEdited) public commissionEdited;

    /**
     * @dev Maps an operator address to a mapping, where the key is the token address and the
     * value is the amount of delegated tokens.
     * @notice This allows tracking of how much each operator has been delegated by all
     * delegators for each of the whitelisted tokens.
     */
    // delegationsByOperator means it is indexed by operator address and not that is is
    // a delegation made by the operator.
    mapping(string exoAddress => mapping(address tokenAddress => uint256 amount)) public delegationsByOperator;

    // depositor and delegation information
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
    mapping(address depositor => bool hasDeposited) public isDepositor;

    /**
     * @dev Maps depositor addresses to another mapping, where the key is an token address and
     * the value is the total amount of that token deposited by the depositor.
     * @notice This mapping is used to keep track of the total deposits made by each account
     * for each token.
     */
    mapping(address depositor => mapping(address tokenAddress => uint256 amount)) public totalDepositAmounts;

    /**
     * @dev Maps depositor addresses to another mapping, where the key is an token address and
     * the value is the total amount of that token deposited and free to bond by the depositor.
     * @notice Use this to check the amount available for withdrawal by each account for each
     * token. The amount available for withdrawal is the total deposited amount minus the
     * amount already delegated.
     */
    mapping(address depositor => mapping(address tokenAddress => uint256 amount)) public withdrawableAmounts;

    /**
     * @dev Maps a delegator address to a nested mapping, where the first key the operator
     * address and the second key is the token's address, pointing to the amount of tokens
     * delegated.
     * @notice This allows tracking of how much each delegator has delegated to each operator
     * for all of the whitelisted tokens.
     */
    mapping(address delegator => mapping(string exoAddress => mapping(address tokenAddress => uint256))) public
        delegations;

    // bootstrapping information - including status, address of proxy, implementation, and
    // initialization
    /**
     * @dev A boolean indicating whether the Exocore chain has been bootstrapped.
     * @notice This flag is used to determine whether the implementation of this contract
     * has been switched over to the client chain gateway.
     */
    bool public bootstrapped;

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
    bytes public clientChainInitializationData;

    /* -------------------------------------------------------------------------- */
    /*         shared state variables for Bootstrap and ClientChainGateway        */
    /* -------------------------------------------------------------------------- */

    // whitelisted tokens and their vaults, and total deposits of said tokens
    /**
     * @dev An array containing all the token addresses that have been added to the whitelist.
     * @notice Use this array to iterate through all whitelisted tokens.
     * This helps in operations like audits, UI display, or when removing tokens
     * from the whitelist needs an indexed approach.
     */
    address[] public whitelistTokens;

    /**
     * @dev Stores a mapping of whitelisted token addresses to their status.
     * @notice Use this to check if a token is allowed for processing.
     * Each token address maps to a boolean indicating whether it is whitelisted.
     */
    mapping(address token => bool whitelisted) public isWhitelistedToken;

    /**
     * @dev Maps token addresses to their corresponding vault contracts.
     * @notice Access the vault interface for a specific token using this mapping.
     * Each token address maps to an IVault contract instance handling its operations.
     */
    mapping(address token => IVault vault) public tokenToVault;

    // cross-chain level information
    /**
     * @dev Stores the Layer Zero chain ID of the Exocore chain.
     * @notice Used to identify the specific Exocore chain this contract interacts with for
     * cross-chain functionalities.
     */
    uint32 public immutable EXOCORE_CHAIN_ID;

    /**
     * @dev A mapping of source chain id to source sender to the nonce of the last inbound
     * message processed from that sender, over LayerZero.
     * @notice This mapping is used to track the last message processed from each sender on
     * each source chain to prevent replay attacks.
     */
    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) public inboundNonce;

    // the beacon that stores the Vault implementation contract address for proxy
    /**
     * @notice this stores the Vault implementation contract address for proxy, and it is
     * shared among all beacon proxies.
     */
    IBeacon public immutable VAULT_BEACON;

    /**
     * @notice a stantalone contract that is dedicated for providing the bytecode of beacon proxy contract
     * @dev we do not store bytecode of beacon proxy contract in this storage because that would cause the code size
     * of this contract exeeding limit and leading to creation failure
     */
    BeaconProxyBytecode public immutable BEACON_PROXY_BYTECODE;

    bytes public constant EXO_ADDRESS_PREFIX = bytes("exo1");

    /* -------------------------------------------------------------------------- */
    /*                                   Events                                   */
    /* -------------------------------------------------------------------------- */

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
     * @notice Emitted when the offset duration before the Exocore spawn time, during which
     * operations are restricted, is updated.
     *
     * @dev This event is triggered whenever the contract owner updates the offset duration that
     * defines the operational lock period leading up to the Exocore chain's launch. The
     * offset duration determines how long before the spawn time the contract will restrict
     * certain operations to ensure stability and integrity. This event logs the new offset
     * duration for transparency and traceability.
     *
     * @param newOffsetDuration The new offset duration (in seconds) that has been set. This value
     * represents the duration before the Exocore spawn time during which certain contract
     * operations are locked.
     */
    event OffsetDurationUpdated(uint256 newOffsetDuration);

    /**
     * @notice Emitted when a deposit is made into the contract.
     * @dev This event is triggered whenever a depositor makes a deposit into the contract.
     * @param success Whether the operation succeeded.
     * @param token The address of the token being deposited, on this chain.
     * @param depositor The address of the depositor, on this chain.
     * @param amount The amount of the token accepted as deposit.
     */
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);

    /**
     * @notice Emitted when a withdrawal is made from the contract.
     * @dev This event is triggered whenever a withdrawer withdraws from the contract.
     * @param success Whether the operation succeeded.
     * @param token The address of the token being withdrawn, on this chain.
     * @param withdrawer The address of the withdrawer, on this chain.
     * @param amount The amount of the token available to claim.
     */
    event WithdrawPrincipalResult(
        bool indexed success, address indexed token, address indexed withdrawer, uint256 amount
    );

    /**
     * @notice Emitted when a delegation is made to an operator.
     * @dev This event is triggered whenever a delegator delegates tokens to an operator.
     * @param success Whether the operation succeeded.
     * @param delegator The address of the delegator, on this chain.
     * @param delegatee The Exocore address of the operator.
     * @param token The address of the token being delegated, on this chain.
     * @param amount The amount of the token delegated.
     */
    event DelegateResult(
        bool indexed success, address indexed delegator, string indexed delegatee, address token, uint256 amount
    );

    /**
     * @notice Emitted when a delegation is removed from an operator.
     * @dev This event is triggered whenever a delegator removes a delegation from an operator.
     * @param success Whether the operation succeeded.
     * @param undelegator The address of the delegator, on this chain.
     * @param undelegatee The Exocore address of the operator..
     * @param token The address of the token being undelegated, on this chain.
     * @param amount The amount of the token undelegated.
     */
    event UndelegateResult(
        bool indexed success, address indexed undelegator, string indexed undelegatee, address token, uint256 amount
    );

    /**
     * @notice Emitted when a deposit + delegation is made.
     * @dev This event is triggered whenever a delegator deposits and then delegates tokens to an operator.
     * @param delegateSuccess Whether the delegation succeeded (deposits always succeed!).
     * @param delegator The address of the delegator, on this chain.
     * @param delegatee The Exocore address of the operator.
     * @param token The address of the token being delegated, on this chain.
     * @param delegatedAmount The amount of the token delegated.
     */
    event DepositThenDelegateResult(
        bool indexed delegateSuccess,
        address indexed delegator,
        string indexed delegatee,
        address token,
        uint256 delegatedAmount
    );

    /**
     * @notice Emitted after the Exocore chain is bootstrapped.
     * @dev This event is triggered after the Exocore chain is bootstrapped, indicating that
     * the contract has successfully transitioned to the Client Chain Gateway logic. Exocore
     * must send a message to the contract to trigger this event.
     */
    event Bootstrapped();

    /**
     * @notice Emitted when the client chain gateway logic + implementation are updated.
     * @dev This event is triggered whenever the client chain gateway logic and implementation
     * are updated. It may be used, before bootstrapping is complete, to upgrade the client
     * chain gateway logic for upgrades or other bugs.
     * @param newLogic Address of the new implementation
     * @param initializationData The abi encoded function which will be called upon upgrade
     */
    event ClientChainGatewayLogicUpdated(address newLogic, bytes initializationData);

    /**
     * @dev Emitted when a new vault is created.
     * @param vault The address of the vault that has been added.
     * @param underlyingToken The underlying token of vault.
     */
    event VaultCreated(address underlyingToken, address vault);

    /**
     * @dev Emitted when a new token is added to the whitelist.
     * @param _token The address of the token that has been added to the whitelist.
     */
    event WhitelistTokenAdded(address _token);

    /* -------------------------------------------------------------------------- */
    /*                                   Errors                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Indicates an operation failed because the specified vault does not exist.
     */
    error VaultNotExist();

    /**
     * @dev Indicates that an operation which is not yet supported is requested.
     */
    error NotYetSupported();

    /**
     * @dev This error is returned when the execution of a layer zero message fails.
     * @param act The action for which the selector or the response function was executed, but
     * failed.
     * @param nonce The nonce of the message that failed.
     * @param reason The reason for the failure.
     * @notice This error is returned when the contract fails to execute a layer zero message
     * due to an error in the execution process.
     */
    error RequestOrResponseExecuteFailed(Action act, uint64 nonce, bytes reason);

    /**
     * @dev Struct to return detailed information about a token, including its name, symbol,
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

    modifier isTokenWhitelisted(address token) {
        require(isWhitelistedToken[token], "BootstrapStorage: token is not whitelisted");
        _;
    }

    modifier isValidAmount(uint256 amount) {
        require(amount > 0, "BootstrapStorage: amount should be greater than zero");
        _;
    }

    modifier vaultExists(address token) {
        require(address(tokenToVault[token]) != address(0), "BootstrapStorage: no vault added for this token");
        _;
    }

    modifier isValidBech32Address(string calldata exocoreAddress) {
        require(isValidExocoreAddress(exocoreAddress), "BootstrapStorage: invalid bech32 encoded Exocore address");
        _;
    }

    constructor(uint32 exocoreChainId_, address vaultBeacon_, address beaconProxyBytecode_) {
        require(exocoreChainId_ != 0, "BootstrapStorage: exocore chain id should not be empty");
        require(
            vaultBeacon_ != address(0), "BootstrapStorage: the vaultBeacon address for beacon proxy should not be empty"
        );
        require(
            beaconProxyBytecode_ != address(0), "BootstrapStorage: the beaconProxyBytecode address should not be empty"
        );

        EXOCORE_CHAIN_ID = exocoreChainId_;
        VAULT_BEACON = IBeacon(vaultBeacon_);
        BEACON_PROXY_BYTECODE = BeaconProxyBytecode(beaconProxyBytecode_);
    }

    function _getVault(address token) internal view returns (IVault) {
        IVault vault = tokenToVault[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }
        return vault;
    }

    function isValidExocoreAddress(string calldata operatorExocoreAddress) public pure returns (bool) {
        bytes memory stringBytes = bytes(operatorExocoreAddress);
        if (stringBytes.length != 42) {
            return false;
        }
        for (uint256 i = 0; i < EXO_ADDRESS_PREFIX.length; i++) {
            if (stringBytes[i] != EXO_ADDRESS_PREFIX[i]) {
                return false;
            }
        }

        return true;
    }

    function _deployVault(address underlyingToken) internal returns (IVault) {
        Vault vault = Vault(
            Create2.deploy(
                0,
                bytes32(uint256(uint160(underlyingToken))),
                // for clarity, this BEACON_PROXY is not related to beacon chain
                // but rather it is the bytecode for the beacon proxy upgrade pattern.
                abi.encodePacked(BEACON_PROXY_BYTECODE.getBytecode(), abi.encode(address(VAULT_BEACON), ""))
            )
        );
        vault.initialize(underlyingToken, address(this));
        emit VaultCreated(underlyingToken, address(vault));

        tokenToVault[underlyingToken] = vault;
        return vault;
    }

}
