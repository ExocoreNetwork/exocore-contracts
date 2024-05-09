pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";

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
    mapping(string exoAddress => mapping(address tokenAddress => uint256 amount)) public
        delegationsByOperator;

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
    mapping(address depositor => mapping(address tokenAddress => uint256 amount)) public
        totalDepositAmounts;

    /**
     * @dev Maps depositor addresses to another mapping, where the key is an token address and
     * the value is the total amount of that token deposited and free to bond by the depositor.
     * @notice Use this to check the amount available for withdrawal by each account for each
     * token. The amount available for withdrawal is the total deposited amount minus the
     * amount already delegated.
     */
    mapping(address depositor => mapping(address tokenAddress => uint256 amount)) public
        withdrawableAmounts;

    /**
     * @dev Maps a delegator address to a nested mapping, where the first key the operator
     * address and the second key is the token's address, pointing to the amount of tokens
     * delegated.
     * @notice This allows tracking of how much each delegator has delegated to each operator
     * for all of the whitelisted tokens.
     */
    mapping(
        address delegator => mapping(
            string exoAddress => mapping(
                address tokenAddress => uint256
            )
        )
    ) public delegations;

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
    bytes clientChainInitializationData;

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
    uint32 public immutable exocoreChainId;

    /**
     * @dev A mapping of source chain id to source sender to the nonce of the last inbound
     * message processed from that sender, over LayerZero.
     * @notice This mapping is used to track the last message processed from each sender on
     * each source chain to prevent replay attacks.
     */
    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) inboundNonce;

    // TSS information.
    /**
     * @dev The message nonce from the last TSS message processed by the contract.
     * @notice This nonce is used to track the last message processed by the contract to
     * prevent replay attacks.
     */
    uint256 lastMessageNonce;

    // the beacon that stores the Vault implementation contract address for proxy
    /**
     * @notice this stores the Vault implementation contract address for proxy, and it is 
     * shsared among all beacon proxies as an immutable.
     */
    IBeacon public immutable vaultBeacon;

    /**
     * @notice Stored code of type(BeaconProxy).creationCode
     * @dev Maintained as a constant to solve an edge case - changes to OpenZeppelin's BeaconProxy code should not cause
     * addresses of EigenPods that are pre-computed with Create2 to change, even upon upgrading this contract, changing compiler version, etc.
     */
    bytes constant BEACON_PROXY_BYTECODE =
        hex"608060405260405161090e38038061090e83398101604081905261002291610460565b61002e82826000610035565b505061058a565b61003e83610100565b6040516001600160a01b038416907f1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e90600090a260008251118061007f5750805b156100fb576100f9836001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100c5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100e99190610520565b836102a360201b6100291760201c565b505b505050565b610113816102cf60201b6100551760201c565b6101725760405162461bcd60e51b815260206004820152602560248201527f455243313936373a206e657720626561636f6e206973206e6f74206120636f6e6044820152641d1c9858dd60da1b60648201526084015b60405180910390fd5b6101e6816001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101b3573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d79190610520565b6102cf60201b6100551760201c565b61024b5760405162461bcd60e51b815260206004820152603060248201527f455243313936373a20626561636f6e20696d706c656d656e746174696f6e206960448201526f1cc81b9bdd08184818dbdb9d1c9858dd60821b6064820152608401610169565b806102827fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d5060001b6102de60201b6100641760201c565b80546001600160a01b0319166001600160a01b039290921691909117905550565b60606102c883836040518060600160405280602781526020016108e7602791396102e1565b9392505050565b6001600160a01b03163b151590565b90565b6060600080856001600160a01b0316856040516102fe919061053b565b600060405180830381855af49150503d8060008114610339576040519150601f19603f3d011682016040523d82523d6000602084013e61033e565b606091505b5090925090506103508683838761035a565b9695505050505050565b606083156103c65782516103bf576001600160a01b0385163b6103bf5760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610169565b50816103d0565b6103d083836103d8565b949350505050565b8151156103e85781518083602001fd5b8060405162461bcd60e51b81526004016101699190610557565b80516001600160a01b038116811461041957600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561044f578181015183820152602001610437565b838111156100f95750506000910152565b6000806040838503121561047357600080fd5b61047c83610402565b60208401519092506001600160401b038082111561049957600080fd5b818501915085601f8301126104ad57600080fd5b8151818111156104bf576104bf61041e565b604051601f8201601f19908116603f011681019083821181831017156104e7576104e761041e565b8160405282815288602084870101111561050057600080fd5b610511836020830160208801610434565b80955050505050509250929050565b60006020828403121561053257600080fd5b6102c882610402565b6000825161054d818460208701610434565b9190910192915050565b6020815260008251806020840152610576816040850160208701610434565b601f01601f19169190910160400192915050565b61034e806105996000396000f3fe60806040523661001357610011610017565b005b6100115b610027610022610067565b610100565b565b606061004e83836040518060600160405280602781526020016102f260279139610124565b9392505050565b6001600160a01b03163b151590565b90565b600061009a7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50546001600160a01b031690565b6001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100fb9190610249565b905090565b3660008037600080366000845af43d6000803e80801561011f573d6000f35b3d6000fd5b6060600080856001600160a01b03168560405161014191906102a2565b600060405180830381855af49150503d806000811461017c576040519150601f19603f3d011682016040523d82523d6000602084013e610181565b606091505b50915091506101928683838761019c565b9695505050505050565b6060831561020d578251610206576001600160a01b0385163b6102065760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064015b60405180910390fd5b5081610217565b610217838361021f565b949350505050565b81511561022f5781518083602001fd5b8060405162461bcd60e51b81526004016101fd91906102be565b60006020828403121561025b57600080fd5b81516001600160a01b038116811461004e57600080fd5b60005b8381101561028d578181015183820152602001610275565b8381111561029c576000848401525b50505050565b600082516102b4818460208701610272565b9190910192915050565b60208152600082518060208401526102dd816040850160208701610272565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a2646970667358221220d51e81d3bc5ed20a26aeb05dce7e825c503b2061aa78628027300c8d65b9d89a64736f6c634300080c0033416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";


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
    event DepositResult(
        bool indexed success, address indexed token, address indexed depositor, uint256 amount
    );

    /**
     * @notice Emitted when a withdrawal is made from the contract.
     * @dev This event is triggered whenever a withdrawer withdraws from the contract.
     * @param success Whether the operation succeeded.
     * @param token The address of the token being withdrawn, on this chain.
     * @param withdrawer The address of the withdrawer, on this chain.
     * @param amount The amount of the token available to claim.
     */
    event WithdrawPrincipleResult(
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
        bool indexed success, address indexed delegator, string delegatee,
        address token, uint256 amount
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

    constructor(
        uint32 exocoreChainId_, 
        address vaultBeacon_
    ) {
        require(exocoreChainId_ != 0, "BootstrapStorage: exocore chain id should not be empty");
        require(vaultBeacon_ != address(0), "BootstrapStorage: the vaultBeacon address for beacon proxy should not be empty");

        exocoreChainId = exocoreChainId_;
        vaultBeacon = IBeacon(vaultBeacon_);
    }
}