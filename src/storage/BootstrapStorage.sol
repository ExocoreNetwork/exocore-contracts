// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Vault} from "../core/Vault.sol";

import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IValidatorRegistry} from "../interfaces/IValidatorRegistry.sol";
import {IVault} from "../interfaces/IVault.sol";

import {BeaconProxyBytecode} from "../utils/BeaconProxyBytecode.sol";

import {Errors} from "../libraries/Errors.sol";
import {GatewayStorage} from "./GatewayStorage.sol";
import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/// @title BootstrapStorage
/// @notice The storage contract for the Bootstrap contract. It later upgrades to ClientChainGatewayStorage.
/// @dev This contract is used as the base storage and is inherited by the storage for Bootstrap and ExocoreGateway.
/// @author ExocoreNetwork
contract BootstrapStorage is GatewayStorage {

    /* -------------------------------------------------------------------------- */
    /*               state variables exclusively owned by Bootstrap               */
    /* -------------------------------------------------------------------------- */

    // time and duration
    /// @notice A timestamp representing the scheduled spawn time of the Exocore chain, which influences the contract's
    /// operational restrictions.
    /// @dev `offsetDuration` before `spawnTime`, the contract freezes and most actions are prohibited.
    uint256 public spawnTime;

    /// @notice The amount of time before the Exocore spawn time during which operations are restricted.
    /// @dev The duration before the Exocore spawn time during which most contract operations are locked.
    uint256 public offsetDuration;

    /// @notice This mapping is used to track the deposits made by all depositors for each token.
    /// @dev A mapping of token addresses to the total amount of that token deposited into the contract.
    mapping(address tokenAddress => uint256 amount) public depositsByToken;

    /// @notice This array stores the Ethereum addresses of all validators that have been registered in the contract.
    /// These validators, sorted by their vote power, will be used to initialize the Exocore chain's validator set.
    /// @dev A public array holding the Ethereum addresses of all validators that have been registered in the contract.
    address[] public registeredValidators;

    /// @notice This mapping is used to track which Ethereum address is linked to which Exocore address.
    /// @dev Maps Ethereum addresses to their corresponding Exocore addresses.
    mapping(address ethAddress => string exoAddress) public ethToExocoreAddress;

    /// @notice Use this mapping to access or modify validator details associated with a specific Exocore address.
    /// @dev Maps Exocore addresses to their corresponding validator details stored in a `Validator` struct.
    mapping(string exoAddress => IValidatorRegistry.Validator validator) public validators;

    /// @notice This mapping is used to enforce a once-only commission rate change for validators before the chain
    /// bootstrap.
    /// @dev A mapping of validator Exocore address to a boolean indicating whether said validator has edited their
    /// commission rate.
    mapping(string exoAddress => bool hasEdited) public commissionEdited;

    /// @notice This allows tracking of how much each validator has been delegated by all delegators for each of the
    /// whitelisted tokens.
    /// @dev Maps a validator address to a mapping, where the key is the token address and the value is the amount of
    /// delegated tokens.
    mapping(string exoAddress => mapping(address tokenAddress => uint256 amount)) public delegationsByValidator;

    /// @notice This array stores all unique depositor addresses to manage and track staking participation.
    /// @dev List of addresses that have staked or deposited into the contract.
    address[] public depositors;

    /// @notice Use this mapping to check if a specific address has deposited into the contract.
    /// @dev A mapping of depositor addresses to a boolean indicating whether the address has deposited into the
    /// contract.
    mapping(address depositor => bool hasDeposited) public isDepositor;

    /// @notice This mapping is used to keep track of the total deposits made by each account for each token.
    /// @dev Maps depositor addresses to another mapping, where the key is a token address and the value is the total
    /// amount of that token deposited by the depositor.
    mapping(address depositor => mapping(address tokenAddress => uint256 amount)) public totalDepositAmounts;

    /// @notice Use this to check the amount available for withdrawal by each account for each token. The amount
    /// available for withdrawal is the total deposited amount minus the amount already delegated.
    /// @dev Maps depositor addresses to another mapping, where the key is a token address and the value is the total
    /// amount of that token deposited and free to bond by the depositor.
    mapping(address depositor => mapping(address tokenAddress => uint256 amount)) public withdrawableAmounts;

    /// @notice This allows tracking of how much each delegator has delegated to each validator for all of the
    /// whitelisted tokens.
    /// @dev Maps a delegator address to a nested mapping, where the first key is the validator address and the second
    /// key is the token's address, pointing to the amount of tokens delegated.
    mapping(address delegator => mapping(string exoAddress => mapping(address tokenAddress => uint256 amount))) public
        delegations;

    /// @notice This flag is used to determine whether the implementation of this contract has been switched over to the
    /// client chain gateway.
    /// @dev A boolean indicating whether the Exocore chain has been bootstrapped.
    bool public bootstrapped;

    /// @notice This proxy admin facilitates the implementation switch from Bootstrap to ClientChainGateway based on
    /// certain conditions.
    /// @dev Address of the custom proxy admin used to manage upgradeability of this contract.
    address public customProxyAdmin;

    /// @notice This address points to the logic contract that the proxy should switch to upon successful bootstrapping.
    /// @dev Address of the Client Chain Gateway logic implementation.
    address public clientChainGatewayLogic;

    /// @notice This data is used to initialize the new logic contract (ClientChainGateway) when the proxy admin
    /// switches the implementation post-bootstrapping.
    /// @dev Contains the initialization data for the Client Chain Gateway logic when upgrading.
    bytes public clientChainInitializationData;

    /* -------------------------------------------------------------------------- */
    /*         shared state variables for Bootstrap and ClientChainGateway        */
    /* -------------------------------------------------------------------------- */

    // whitelisted tokens and their vaults, and total deposits of said tokens
    /// @notice Use this array to iterate through all whitelisted tokens. This helps in operations like audits, UI
    /// display, or when removing tokens from the whitelist needs an indexed approach.
    /// @dev An array containing all the token addresses that have been added to the whitelist.
    address[] public whitelistTokens;

    /// @notice Use this to check if a token is allowed for processing. Each token address maps to a boolean indicating
    /// whether it is whitelisted.
    /// @dev Stores a mapping of whitelisted token addresses to their status.
    mapping(address token => bool whitelisted) public isWhitelistedToken;

    /// @notice Access the vault interface for a specific token using this mapping. Each token address maps to an IVault
    /// contract instance handling its operations.
    /// @dev Maps token addresses to their corresponding vault contracts.
    mapping(address token => IVault vault) public tokenToVault;

    /// @notice Mapping of owner addresses to their corresponding ExoCapsule contracts.
    /// @dev Maps owner addresses to their corresponding ExoCapsule contracts.
    mapping(address owner => IExoCapsule capsule) public ownerToCapsule;

    /// @notice The beacon for the ExoCapsule contract, which stores the ExoCapsule implementation.
    IBeacon public immutable EXO_CAPSULE_BEACON;

    /// @notice The address of the beacon chain oracle.
    address public immutable BEACON_ORACLE_ADDRESS;

    /// @dev The (virtual) address for native staking token.
    address internal constant VIRTUAL_NST_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @dev The address of the ETHPOS deposit contract.
    IETHPOSDeposit internal constant ETH_POS = IETHPOSDeposit(0x00000000219ab540356cBB839Cbe05303d7705Fa);

    /// @notice Used to identify the specific Exocore chain this contract interacts with for cross-chain
    /// functionalities.
    /// @dev Stores the Layer Zero chain ID of the Exocore chain.
    uint32 public immutable EXOCORE_CHAIN_ID;

    /// @notice This stores the Vault implementation contract address for proxy, and it is shared among all beacon
    /// proxies.
    IBeacon public immutable VAULT_BEACON;

    /// @notice A standalone contract that is dedicated for providing the bytecode of beacon proxy contract.
    /// @dev We do not store bytecode of beacon proxy contract in this storage because that would cause the code size of
    /// this contract exceeding the limit and leading to creation failure.
    BeaconProxyBytecode public immutable BEACON_PROXY_BYTECODE;

    /// @notice Mapping to keep track of the consensus keys that have been used.
    /// @dev A mapping of consensus keys to a boolean indicating whether the key has been used.
    mapping(bytes32 consensusKey => bool used) public consensusPublicKeyInUse;

    /// @notice Mapping to keep track of the validator names that have been used.
    /// @dev A mapping of validator names to a boolean indicating whether the name has been used.
    mapping(string name => bool used) public validatorNameInUse;

    /* -------------------------------------------------------------------------- */
    /*                                   Events                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Emitted when the spawn time of the Exocore chain is updated.
    /// @dev This event is triggered whenever the contract owner updates the spawn time of the Exocore chain.
    /// @param newSpawnTime The new time (in UNIX seconds) that has been set.
    event SpawnTimeUpdated(uint256 newSpawnTime);

    /// @notice Emitted when the offset duration before the Exocore spawn time, during which operations are restricted,
    /// is updated.
    /// @dev This event is triggered whenever the contract owner updates the offset duration.
    /// @param newOffsetDuration The new offset duration (in seconds) that has been set.
    event OffsetDurationUpdated(uint256 newOffsetDuration);

    /// @notice Emitted when a deposit is made into the contract.
    /// @dev This event is triggered whenever a depositor makes a deposit into the contract.
    /// @param success Whether the operation succeeded.
    /// @param token The address of the token being deposited, on this chain.
    /// @param depositor The address of the depositor, on this chain.
    /// @param amount The amount of the token accepted as deposit.
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);

    /// @notice Emitted when a withdrawal is made from the contract.
    /// @dev This event is triggered whenever a withdrawer withdraws from the contract.
    /// @param success Whether the operation succeeded.
    /// @param token The address of the token being withdrawn, on this chain.
    /// @param withdrawer The address of the withdrawer, on this chain.
    /// @param amount The amount of the token available to claim.
    event ClaimPrincipalResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);

    /// @notice Emitted when a delegation is made to an operator.
    /// @dev This event is triggered whenever a delegator delegates tokens to an operator.
    /// @param success Whether the operation succeeded.
    /// @param delegator The address of the delegator, on this chain.
    /// @param delegatee The Exocore address of the operator.
    /// @param token The address of the token being delegated, on this chain.
    /// @param amount The amount of the token delegated.
    event DelegateResult(
        bool indexed success, address indexed delegator, string indexed delegatee, address token, uint256 amount
    );

    /// @notice Emitted when a delegation is removed from an operator.
    /// @dev This event is triggered whenever a delegator removes a delegation from an operator.
    /// @param success Whether the operation succeeded.
    /// @param undelegator The address of the delegator, on this chain.
    /// @param undelegatee The Exocore address of the operator.
    /// @param token The address of the token being undelegated, on this chain.
    /// @param amount The amount of the token undelegated.
    event UndelegateResult(
        bool indexed success, address indexed undelegator, string indexed undelegatee, address token, uint256 amount
    );

    /// @notice Emitted when a deposit + delegation is made.
    /// @dev This event is triggered whenever a delegator deposits and then delegates tokens to an operator.
    /// @param delegateSuccess Whether the delegation succeeded (deposits always succeed!).
    /// @param delegator The address of the delegator, on this chain.
    /// @param delegatee The Exocore address of the operator.
    /// @param token The address of the token being delegated, on this chain.
    /// @param delegatedAmount The amount of the token delegated.
    event DepositThenDelegateResult(
        bool indexed delegateSuccess,
        address indexed delegator,
        string indexed delegatee,
        address token,
        uint256 delegatedAmount
    );

    /// @notice Emitted after the Exocore chain is bootstrapped.
    /// @dev This event is triggered after the Exocore chain is bootstrapped, indicating that the contract has
    /// successfully transitioned to the Client Chain Gateway logic. Exocore must send a message to the contract to
    /// trigger this event.
    event Bootstrapped();

    /// @notice Emitted when a mark bootstrap call is received before the spawn time.
    /// @dev This event is triggered when a mark bootstrap call is received before the spawn time.
    event BootstrapNotTimeYet();

    /// @notice Emitted if the bootstrap upgrade to client chain gateway fails.
    /// @dev This event is triggered if the upgrade from Bootstrap to Client Chain Gateway fails. It is not an error
    /// intentionally to prevent blocking the system.
    event BootstrapUpgradeFailed();

    /// @notice Emitted when the contract is already bootstrapped.
    /// @dev This event is triggered when the contract is already bootstrapped and an attempt is made to bootstrap it
    /// again. It is not an error intentionally to prevent blocking the system.
    event BootstrappedAlready();

    /// @notice Emitted when the client chain gateway logic + implementation are updated.
    /// @dev This event is triggered whenever the client chain gateway logic and implementation are updated. It may be
    /// used, before bootstrapping is complete, to upgrade the client chain gateway logic for upgrades or other bugs.
    /// @param newLogic Address of the new implementation
    /// @param initializationData The abi encoded function which will be called upon upgrade
    event ClientChainGatewayLogicUpdated(address newLogic, bytes initializationData);

    /// @dev Emitted when a new vault is created.
    /// @param vault The address of the vault that has been added.
    /// @param underlyingToken The underlying token of vault.
    event VaultCreated(address underlyingToken, address vault);

    /// @dev Emitted when a new token is added to the whitelist.
    /// @param _token The address of the token that has been added to the whitelist.
    event WhitelistTokenAdded(address _token);

    /* ---------------------------- native restaking events ---------------------------- */
    /// @notice Emitted when a new ExoCapsule is created.
    /// @param owner Owner of the ExoCapsule.
    /// @param capsule Address of the ExoCapsule.
    event CapsuleCreated(address owner, address capsule);

    /// @notice Emitted when a staker stakes with a capsule.
    /// @param staker Address of the staker.
    /// @param capsule Address of the capsule.
    event StakedWithCapsule(address staker, address capsule);

    /// @dev Struct to return detailed information about a token, including its name, symbol, address, decimals, total
    /// supply, and additional metadata for cross-chain operations and contextual data.
    /// @param name The name of the token.
    /// @param symbol The symbol of the token.
    /// @param tokenAddress The contract address of the token.
    /// @param decimals The number of decimals the token uses.
    /// @param depositAmount The total amount of the token deposited into the contract.
    struct TokenInfo {
        string name;
        string symbol;
        address tokenAddress;
        uint8 decimals;
        uint256 depositAmount;
    }

    /**
     * @dev Struct to store the parameters to initialize the immutable variables for the contract.
     * @param exocoreChainId_ The chain ID of the Exocore chain.
     * @param beaconOracleAddress_ The address of the beacon chain oracle.
     * @param vaultBeacon_ The address of the vault beacon.
     * @param exoCapsuleBeacon_ The address of the ExoCapsule beacon.
     * @param beaconProxyBytecode_ The address of the beacon proxy bytecode contract.
     */
    struct ImmutableConfig {
        uint32 exocoreChainId;
        address beaconOracleAddress;
        address vaultBeacon;
        address exoCapsuleBeacon;
        address beaconProxyBytecode;
    }

    /// @dev Storage gap to allow for future upgrades.
    uint256[40] private __gap;

    /// @dev Ensures that native restaking is enabled for this contract.
    modifier nativeRestakingEnabled() {
        if (!isWhitelistedToken[VIRTUAL_NST_ADDRESS]) {
            revert Errors.NativeRestakingControllerNotWhitelisted();
        }
        _;
    }

    /// @notice Checks if the token is whitelisted.
    /// @param token The address of the token to check.
    modifier isTokenWhitelisted(address token) {
        require(isWhitelistedToken[token], "BootstrapStorage: token is not whitelisted");
        _;
    }

    /// @notice Ensures the amount is greater than zero.
    /// @param amount The amount to check.
    modifier isValidAmount(uint256 amount) {
        require(amount > 0, "BootstrapStorage: amount should be greater than zero");
        _;
    }

    /// @notice Checks if a vault exists for the given token.
    /// @param token The address of the token to check.
    modifier vaultExists(address token) {
        require(address(tokenToVault[token]) != address(0), "BootstrapStorage: no vault added for this token");
        _;
    }

    /// @notice Initializes the contract with the given parameters.
    /// @param params The parameters to initialize the contract immutable variables.
    constructor(ImmutableConfig memory params) {
        require(params.exocoreChainId != 0, "BootstrapStorage: exocore chain id should not be empty");
        require(params.beaconOracleAddress != address(0), "BootstrapStorage: the beaconOracleAddress address should not be empty");
        require(params.vaultBeacon != address(0), "BootstrapStorage: the vaultBeacon address for beacon proxy should not be empty");
        require(params.beaconProxyBytecode != address(0), "BootstrapStorage: the beaconProxyBytecode address should not be empty");
        require(params.exoCapsuleBeacon != address(0), "BootstrapStorage: the exoCapsuleBeacon address should not be empty");

        EXOCORE_CHAIN_ID = params.exocoreChainId;
        BEACON_ORACLE_ADDRESS = params.beaconOracleAddress;
        VAULT_BEACON = IBeacon(params.vaultBeacon);
        EXO_CAPSULE_BEACON = IBeacon(params.exoCapsuleBeacon);
        BEACON_PROXY_BYTECODE = BeaconProxyBytecode(params.beaconProxyBytecode);
    }

    /// @notice Returns the vault associated with the given token.
    /// @dev Reverts if the vault does not exist.
    /// @param token The address of the token.
    /// @return The vault associated with the given token.
    function _getVault(address token) internal view returns (IVault) {
        IVault vault = tokenToVault[token];
        if (address(vault) == address(0)) {
            revert Errors.VaultDoesNotExist();
        }
        return vault;
    }

    /// @dev Returns the ExoCapsule for the given owner, if it exists. Fails if the ExoCapsule does not exist.
    /// @param owner The owner of the ExoCapsule.
    function _getCapsule(address owner) internal view returns (IExoCapsule) {
        IExoCapsule capsule = ownerToCapsule[owner];
        if (address(capsule) == address(0)) {
            revert Errors.CapsuleDoesNotExist();
        }
        return capsule;
    }

    /// @notice Deploys a new vault for the given underlying token.
    /// @dev Uses the Create2 opcode to deploy the vault.
    /// @param underlyingToken The address of the underlying token.
    /// @param tvlLimit The TVL limit for the vault.
    /// @return The address of the newly deployed vault.
    // The bytecode returned by `BEACON_PROXY_BYTECODE` and `EXO_CAPSULE_BEACON` address are actually fixed size of byte
    // array, so it would not cause collision for encodePacked
    // slither-disable-next-line encode-packed-collision
    function _deployVault(address underlyingToken, uint256 tvlLimit) internal returns (IVault) {
        if (underlyingToken == VIRTUAL_NST_ADDRESS) {
            revert Errors.ForbidToDeployVault();
        }

        Vault vault = Vault(
            Create2.deploy(
                0,
                bytes32(uint256(uint160(underlyingToken))),
                // for clarity, this BEACON_PROXY is not related to beacon chain
                // but rather it is the bytecode for the beacon proxy upgrade pattern.
                abi.encodePacked(BEACON_PROXY_BYTECODE.getBytecode(), abi.encode(address(VAULT_BEACON), ""))
            )
        );
        vault.initialize(underlyingToken, tvlLimit, address(this));
        emit VaultCreated(underlyingToken, address(vault));

        tokenToVault[underlyingToken] = vault;
        return vault;
    }

    /// @dev Internal version of getWhitelistedTokensCount; shared between Bootstrap and ClientChainGateway
    /// @dev Looks a bit redundant because it is, but at least this way, the implementation is shared.
    function _getWhitelistedTokensCount() internal view returns (uint256) {
        return whitelistTokens.length;
    }

}
