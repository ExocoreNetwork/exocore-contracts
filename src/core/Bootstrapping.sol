// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Do not use IERC20 because it does not expose the decimals() function.
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract Bootstrapping is Ownable, Pausable {
    using SafeERC20 for ERC20;

    /**
     * @dev Represents the state of the the Exocore chain. The chain is considered bootstrapped
     * when at least 1 block is produced, and the validators collectively send a transaction to
     * the client chain to indicate that the chain is bootstrapped. The transaction may be sent
     * via LayerZero or using TSS, none of which have yet been implemented.
    */
    bool public bootstrapped = false;

    /**
     * @dev The address from which a bootstrapping request is expected to be sent. This address
     * is expected to be the LayerZero contract address, which will be used to send the
     * bootstrapping request to the client chain.
    */
    address bootstrappingAddress;

    /**
     * @dev Represents commission details, represented as 18 decimals.
     * @param rate The current commission rate.
     * @param maxRate The maximum allowable commission rate.
     * @param maxChangeRate The maximum rate at which the commission rate can change.
     * All rates must be less than or equal to 1e18.
     * For example, a 10% commission rate would be represented as 1e17.
     * rate must not exceed maxRate, and maxChangeRate must not exceed maxRate.
    */
    struct Commission {
        uint256 rate;
        uint256 maxRate;
        uint256 maxChangeRate;
    }

    /**
     * @dev Represents an operator in the system, including their registration status,
     * consensus public key for the Exocore chain, Exocore chain address, commission rate,
     * and identifying information such as name and website.
     *
     * @param isRegistered Indicates whether the operator is currently registered.
     * @param consensusPublicKey The public key used by the operator for consensus
     *                           on the Exocore chain.
     * @param exocoreAddress The operator's address on the Exocore chain.
     * @param name The name (meta info) for the operator.
     * @param commission The commission for the operator.
     */
    struct Operator {
        bool isRegistered;
        bytes32 consensusPublicKey;
        address exocoreAddress;
        string name;
        Commission commission;
    }

    /**
     * @dev Represents the deposit details of a token by a user, tracking both the total
     * amount deposited and the amount currently available (not delegated).
     *
     * @param totalDeposit The total amount of the token deposited by the user.
     * @param availableFunds The portion of the total deposit that is currently available
     *                       for use.
     */
    struct TokenDeposit {
        uint256 totalDeposit;
        uint256 availableFunds;
    }

    /**
     * @dev Contains information about a validator, specifically their public key and
     * the total vote power, which is calculated based on the total amount delegated to them.
     *
     * @param pubKey The public key of the validator.
     * @param votePower The total vote power of the validator, aggregated from all delegations.
     */
    struct Validator {
        bytes32 pubKey;
        uint256 votePower;
    }

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

    /**
     * @dev Struct to represent the amount of a specific token deposited by a user.
     *
     * @param tokenAddress The address of the token deposited.
     * @param amountDeposited The total amount of the token that has been deposited by the user.
     */
    struct DepositorTokenInfo {
        address tokenAddress;
        uint256 amountDeposited;
    }

    /**
     * @dev Struct to capture details about a delegation made by a user, including the token
     * involved in the delegation, the operator to whom the tokens are delegated, and the
     * amount of tokens delegated.
     *
     * @param tokenAddress The address of the token being delegated.
     * @param operatorAddress The address of the operator to whom the tokens are delegated.
     * @param amountDelegated The amount of the token that has been delegated.
     */
    struct DelegationInfo {
        address tokenAddress;
        address operatorAddress;
        uint256 amountDelegated;
    }
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
     * @dev Tracks whether an address has edited their commission settings.
     * A value of `true` indicates the commission has been edited,
     * while `false` indicates it has not been edited.
     */
    mapping(address => bool) private commissionEdited;

    /**
     * @notice A dynamic array of ERC20 token addresses that are supported by the contract
     * for deposit and delegation operations.
     *
     * @dev This array holds the addresses of all the ERC20 tokens that users can deposit
     * into the contract, delegate to operators, or withdraw. The contract owner can add
     * but not remove tokens from this list using addSupportedToken, subject to operational
     * restrictions.
     */
    address[] public supportedTokens;

    /**
     * @notice A mapping from a token's address to the total amount of deposits it has received.
     * This information is used to load the `x/assets` genesis state.
     *
     * @dev This mapping is indexed by the address of a token and stores the total amount of
     * that token that has been deposited into the contract. This information is used to
     * generate the `x/assets` genesis state for the Exocore chain.
     */
    mapping(address => uint256) public depositsByToken;

    /**
     * @notice A mapping from an operator's address to their corresponding Operator struct,
     * which includes registration status, consensus public key, and other relevant information.
     *
     * @dev This mapping stores detailed information about each registered operator, including
     * whether they are currently registered, their consensus public key for the Exocore chain,
     * and additional metadata such as their Exocore address, commission rate, name, and
     * website. Operators can register, update their information, replace their public key, or
     * deregister through the contract's functions.
     */
    mapping(address => Operator) public operators;

    /**
     * @notice A nested mapping that tracks each user's deposited amounts for each supported
     * token, along with the available funds that haven't been delegated.
     *
     * @dev The mapping's first key is the user's address, the second key is the token address,
     * and the value is a TokenDeposit struct that contains the total amount of the token
     * deposited by the user and the amount of the token available for delegation. This
     * structure allows the contract to track both the total deposits and how much of those
     * deposits are currently allocated to delegations.
     */
    mapping(address => mapping(address => TokenDeposit)) public userDeposits;

    /**
     * @notice A triple-nested mapping that records the amount of each token a user has
     * delegated to each operator.
     *
     * @dev The first key is the delegator's address, the second key is the operator's address
     * to whom the tokens are delegated, and the third key is the token address. The value is
     * the amount of the specified token that has been delegated. This mapping enables the
     * contract to manage and track delegations across different tokens and operators.
     */
    mapping(address => mapping(address => mapping(address => uint256)))
        public delegations;

    /**
     * @notice A nested mapping that tracks the total amount of each token delegated to each
     * operator by all users, facilitating reverse lookup of delegated amounts.
     *
     * @dev The first key is the operator's address, and the second key is the token address.
     * The value is the total amount of the specified token that has been delegated to the
     * operator from all delegators. This mapping is useful for calculating the total resources
     * or "vote power" controlled by each operator.
     */
    mapping(address => mapping(address => uint256))
        public totalDelegatedToOperator;

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
     * @dev Stores a list of unique addresses that have made deposits into the contract.
     * This array is used in conjunction with the `isDepositor` mapping to efficiently
     * track and ensure that each depositor's address is only added once, facilitating
     * easy enumeration and identification of all depositors for purposes such as
     * off-chain aggregation, querying, or contract-based analytics.
     */
    address[] private depositors;

    /**
     * @dev Maps an address to a boolean indicating whether it has made a deposit into
     * the contract. This mapping is used to prevent duplicate entries in the `depositors`
     * array, ensuring that each depositor's address is unique and facilitating efficient
     * checks on whether an address has previously deposited. When an address makes a
     * deposit for the first time, it is added to the `depositors` array and this mapping
     * is updated to reflect their depositor status.
     */
    mapping(address => bool) private isDepositor;

    /**
     * @notice Emitted when a new operator is registered in the contract.
     * @param operator The Ethereum address of the operator that was registered.
     */
    event OperatorRegistered(address operator);

    /**
     * @notice Emitted when an operator replaces their consensus public key.
     * @param operator The Ethereum address of the operator whose key was replaced.
     * @param newKey The new consensus public key that replaces the old one.
     */
    event OperatorKeyReplaced(address operator, bytes32 newKey);

    /**
     * @notice Emitted when an operator updates their registration parameters.
     * @param operator The Ethereum address of the operator whose parameters were updated.
     * @param exocoreAddress The new Exocore address of the operator.
     */
    event OperatorExocoreAddressUpdated(
        address operator,
        address exocoreAddress
    );

    /**
     * @notice Emitted when a new token is added to the list of supported tokens.
     * @param token The address of the token that was added to the supported list.
     */
    event TokenAdded(address token);

    /**
     * @notice Emitted when a depositor deposits tokens into the contract.
     * @param depositor The address of the user making the deposit.
     * @param token The address of the token being deposited.
     * @param amount The amount of the token deposited.
     */
    event TokenDepositEvent(address depositor, address token, uint256 amount);

    /**
     * @notice Emitted when a depositor delegates tokens to an operator.
     * @param delegator The address of the user delegating the tokens.
     * @param operator The address of the operator to whom the tokens are delegated.
     * @param token The address of the token being delegated.
     * @param amount The amount of tokens being delegated.
     */
    event Delegated(
        address delegator,
        address operator,
        address token,
        uint256 amount
    );

    /**
     * @notice Emitted when a depositor undelegates tokens from an operator.
     * @param delegator The address of the user undelegating the tokens.
     * @param operator The address of the operator from whom the tokens are undelegated.
     * @param token The address of the token being undelegated.
     * @param amount The amount of tokens being undelegated.
     */
    event Undelegated(
        address delegator,
        address operator,
        address token,
        uint256 amount
    );

    /**
     * @notice Emitted when the spawn time of the Exocore chain is updated.
     * @param newSpawnTime The new spawn time set for the Exocore chain launch.
     */
    event SpawnTimeUpdated(uint256 newSpawnTime);

    /**
     * @notice Emitted when a depositor withdraws tokens from the contract.
     * @param depositor The address of the user making the withdrawal.
     * @param token The address of the token being withdrawn.
     * @param amount The amount of the token withdrawn.
     */
    event Withdrawn(address depositor, address token, uint256 amount);

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
     * @notice Emitted when the contract is bootstrapped.
     */
    event Bootstrapped();

    /**
     * @notice Creates a new instance of the BootstrappingContract, initializing supported
     * tokens, the Exocore spawn time, and the operational offset time.
     *
     * @dev The constructor sets up the initial configuration for the contract, including the
     * list of ERC20 tokens that will be supported for deposit and delegation operations, the
     * scheduled spawn time for the Exocore chain, and the period before this spawn time during
     * which operations are restricted to ensure stability. The offset time provides flexibility
     * in managing the operational lock period, allowing it to be adjusted according to security
     * needs or other considerations. This contract inherits from OpenZeppelin's Ownable and
     * Pausable contracts, leveraging their functionalities for ownership management and
     * pausing/unpausing contract operations.
     *
     * @param tokenAddresses An array of ERC20 token addresses that the contract will initially
     * support for deposit and delegation operations. These tokens can be modified later by the
     * contract owner using dedicated functions.
     * @param spawnTime The UNIX timestamp representing the scheduled spawn time of the Exocore
     * chain. This timestamp is used to calculate the lock period during which certain contract
     * operations are restricted.
     * @param _offsetTime The duration in seconds before the spawn time during which the
     * contract operations are locked. This period is intended to freeze the contract state to
     * ensure stability and integrity before the Exocore chain's launch.
     */
    constructor(
        address[] memory tokenAddresses,
        uint256 spawnTime,
        uint256 _offsetTime,
        address _bootstrappingAddress
    ) {
        supportedTokens = tokenAddresses;
        for(uint256 i = 0; i < tokenAddresses.length; i++) {
            depositsByToken[tokenAddresses[i]] = 0;
        }
        exocoreSpawnTime = spawnTime;
        offsetTime = _offsetTime;
        bootstrappingAddress = _bootstrappingAddress;
    }

    /**
     * @dev Modifier to restrict operations based on the contract's defined timeline.
     * It checks if the current block timestamp is less than 24 hours before the
     * Exocore spawn time, effectively locking operations as the spawn time approaches
     * and afterwards. This is used to enforce a freeze period before the Exocore
     * chain's launch, ensuring no changes can be made during this critical time.
     *
     * The modifier is applied to functions that should be restricted by this timeline,
     * including registration, delegation, and token management operations. Attempting
     * to perform these operations during the lock period will result in a transaction
     * revert with an informative error message.
     */
    modifier operationAllowed() {
        require(
            block.timestamp < exocoreSpawnTime - offsetTime,
            "Operations are locked"
        );
        _;
    }

    /**
     * @dev Modifier to restrict operations to only occur before the Exocore chain has been
     * bootstrapped.
     */
    modifier notBootstrapped() {
        require(!bootstrapped, "Contract already bootstrapped");
        _;
    }

    /**
     * @dev Modifier to restrict operations to only occur from the bootstrapping address.
     */
    modifier onlyBootstrapAddress() {
        require(
            msg.sender == bootstrappingAddress,
            "Only the bootstrapping address can call this function"
        );
        _;
    }

    /**
     * @dev Registers a new operator with the contract. This includes setting their
     * consensus public key, Exocore address, commission rate, name, and website URL.
     * Registration is subject to the contract not being paused and the operation being
     * allowed based on the defined timeline.
     *
     * Following the registration, operators must self delegate. Until an operator
     * self delegates enough tokens, it will not be included in the validator set.
     * This "feature" can act as a mechanism of operator opt-out. There is no operator
     * deregistration feature in this contract (or even in the Cosmos chain).
     *
     * @param consensusPublicKey The operator's public key for consensus on the Exocore chain.
     * @param exocoreAddress The operator's address on the Exocore chain.
     * @param name The name (meta info) for the operator.
     */
    function registerOperator(
        bytes32 consensusPublicKey,
        address exocoreAddress,
        string memory name,
        Commission memory commission
    ) external whenNotPaused operationAllowed notBootstrapped {
        require(
            !operators[msg.sender].isRegistered,
            "Operator already registered"
        );
        // the keys are bytes32 so their length is fixed. no need to validate it.
        require(
            !consensusPublicKeyInUse(consensusPublicKey),
            "Consensus public key already in use"
        );
        require(
            !nameInUse(name),
            "Name already in use"
        );
        require(
            exocoreAddress != address(0),
            "Exocore address cannot be zero"
        );
        require(
            isCommissionValid(commission), "Commission invalid"
        );
        require(
            consensusPublicKey != bytes32(0),
            "Consensus public key cannot be zero"
        );
        operators[msg.sender] = Operator(
            true,
            consensusPublicKey,
            exocoreAddress,
            name,
            commission
        );
        registeredOperators.push(msg.sender);
        emit OperatorRegistered(msg.sender);
    }

    /**
     * @dev Checks if a given consensus public key is already in use by any registered operator.
     *
     * This function iterates over all registered operators stored in the contract's state
     * to determine if the provided consensus public key matches any existing operator's
     * public key. It is designed to ensure the uniqueness of consensus public keys among
     * operators, as each operator must have a distinct consensus public key to maintain
     * integrity and avoid potential conflicts or security issues.
     *
     * @param newKey The consensus public key to check for uniqueness. This key is expected
     * to be provided as a byte32 array (`bytes32`), which is the typical format for
     * storing and handling public keys in Ethereum smart contracts.
     *
     * @return bool Returns `true` if the consensus public key is already in use by an
     * existing operator, indicating that the key is not unique. Returns `false` if the
     * public key is not found among the registered operators, indicating that the key
     * is unique and can be safely used for a new or updating operator.
    */
    function consensusPublicKeyInUse(bytes32 newKey) public view returns (bool) {
        for (uint256 i = 0; i < registeredOperators.length; i++) {
            if (operators[registeredOperators[i]].consensusPublicKey == newKey) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Checks if the given commission settings are valid.
     * @dev Validates that the commission rate, max rate, and max change rate are within acceptable bounds. Each parameter must be less than or equal to 1e18. The commission rate must not exceed the max rate, and the max change rate must not exceed the max rate.
     * @param commission The commission structure containing the rate, max rate, and max change rate to be validated.
     * @return bool Returns `true` if all conditions for a valid commission are met, `false` otherwise.
     */
    function isCommissionValid(Commission memory commission) public pure returns (bool) {
        return
            commission.rate <= 1e18 &&
            commission.maxRate <= 1e18 &&
            commission.maxChangeRate <= 1e18 &&
            commission.rate <= commission.maxRate &&
            commission.maxChangeRate <= commission.maxRate;
    }

    /**
     * @dev Checks if a given name is already in use by any registered operator.
     *
     * This function iterates over all registered operators stored in the contract's state
     * to determine if the provided name matches any existing operator's name. It is
     * designed to ensure the uniqueness of name (identity) among operators, as each
     * operator must have a distinct name to maintain integrity and avoid potential
     * conflicts or security issues.
     *
     * @param newName The name to check for uniqueness, as a string.
     *
     * @return bool Returns `true` if the name is already in use by an existing operator,
     * indicating that the name is not unique. Returns `false` if the name is not found
     * among the registered operators, indicating that the name is unique and can be
     * safely used for a new operator.
    */
    function nameInUse(string memory newName) public view returns (bool) {
        for (uint256 i = 0; i < registeredOperators.length; i++) {
            if (keccak256(abi.encodePacked(operators[registeredOperators[i]].name)) ==
                keccak256(abi.encodePacked(newName))) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Allows an operator to replace their existing consensus public key with a new one.
     * This operation is subject to the contract's timeline restrictions and the contract not
     * being paused.
     *
     * @param newKey The new public key to replace the existing one.
     */
    function replaceKey(
        bytes32 newKey
    ) external whenNotPaused operationAllowed notBootstrapped {
        require(operators[msg.sender].isRegistered, "Operator not registered");
        // if you send a transaction with the same public key, it will revert
        require(
            !consensusPublicKeyInUse(newKey),
            "Consensus public key already in use"
        );
        require(
            consensusPublicKey != bytes32(0),
            "Consensus public key cannot be zero"
        );
        operators[msg.sender].consensusPublicKey = newKey;
        emit OperatorKeyReplaced(msg.sender, newKey);
    }

    /**
     * @dev Updates an operator's Exocore address and is subject
     * to both pausing and timeline restrictions of the contract.
     *
     * @param exocoreAddress The new Exocore address of the operator.
     */
    function updateOperatorExocoreAddress(
        address exocoreAddress
    ) external whenNotPaused operationAllowed notBootstrapped {
        require(operators[msg.sender].isRegistered, "Operator not registered");
        require(
            exocoreAddress != address(0),
            "Exocore address cannot be zero"
        );
        operators[msg.sender].exocoreAddress = exocoreAddress;
        emit OperatorExocoreAddressUpdated(
            msg.sender, exocoreAddress
        );
    }

    /**
     * @notice Updates the commission rate for the calling operator.
     * @dev Can only be called by a registered operator. The function checks if the operation
     * is allowed and not paused. Throws if the operator is not registered or the new rate
     * exceeds the maximum allowed rate. 
     * @param newRate The new commission rate to be set for the calling operator. 
     * Must not exceed the operator's maximum rate.
     */
    function updateRate(
        uint256 newRate
    ) external whenNotPaused operationAllowed notBootstrapped {
        // operator must exist
        require(operators[msg.sender].isRegistered, "Operator not registered");
        // across the lifetime of this contract before network bootstrap,
        // allow the editing of commission only once.
        require(!commissionEdited[msg.sender], "Commission already edited once");
        Commission memory commission = operators[msg.sender].commission;
        uint256 rate = commission.rate;
        uint256 maxRate = commission.maxRate;
        uint256 maxChangeRate = commission.maxChangeRate;
        // newRate <= maxRate <= 1e18
        require(newRate <= maxRate, "Rate exceeds max rate");
        // to prevent operators from blindsiding users by first registering at low rate and
        // subsequently increasing it, we should also check that the change is within the
        // allowed rate change.
        require(
            newRate <= rate + maxChangeRate,
            "Rate change exceeds max change rate"
        );
        operators[msg.sender].commission.rate = newRate;
        commissionEdited[msg.sender] = true;
    }

    /**
     * @dev Adds a new token to the list of supported tokens for operations like
     * depositing and delegating. Only the owner can add supported tokens, and this
     * action is subject to the contract not being paused and operation being allowed
     * based on the defined timeline.
     *
     * @param token The address of the ERC20 token to add to the supported list.
     */
    // TODO: for bootstrap, if we know that we only intend to support X tokens
    // should this even be retained?
    function addSupportedToken(
        address token
    ) external whenNotPaused operationAllowed onlyOwner notBootstrapped {
        require(!isTokenSupported(token), "Token already supported");
        supportedTokens.push(token);
        depositsByToken[token] = 0;
        emit TokenAdded(token);
    }

    /**
     * @dev Sets the bootstrapping address, which is the address from which a bootstrapping
     * request is expected to be sent. This address is expected to be the LayerZero contract
     * address, which will be used to send the bootstrapping request to the client chain.
     * This function can only be called by the contract owner and is subject to the contract
     * not being paused and operation being allowed based on the defined timeline.
     *
     * @param _bootstrappingAddress The address from which a bootstrapping request is expected
     * to be sent.
     */
    function setBootstrappingAddress(address _bootstrappingAddress)
    external onlyOwner whenNotPaused operationAllowed notBootstrapped {
        bootstrappingAddress = _bootstrappingAddress;
    }

    // Do not implement removeSupportedToken because too much complexity for bootstrapping.
    // for example, how to handle withdrawals of the removed token?
    // what if its added back again?

    /**
     * @dev Checks if a given token is supported by the contract for operations like
     * depositing and delegating.
     *
     * @param token The address of the ERC20 token to check.
     * @return bool True if the token is supported, false otherwise.
     */
    function isTokenSupported(address token) public view returns (bool) {
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Allows the contract owner to modify the offset time that determines
     * the lock period before the Exocore spawn time. This function can only be
     * called by the contract owner.
     *
     * @param _offsetTime The new offset time in seconds.
     */
    function setOffsetTime(uint256 _offsetTime) external onlyOwner notBootstrapped {
        offsetTime = _offsetTime;
        emit OffsetTimeUpdated(_offsetTime);
    }

    /**
     * @dev Allows a user to deposit a specified amount of a supported token into the
     * contract. The operation is subject to the contract not being paused and being
     * allowed based on the defined timeline.
     *
     * @param token The address of the ERC20 token to deposit.
     * @param amount The amount of the token to deposit.
     */
    function deposit(
        address token,
        uint256 amount
    ) external whenNotPaused operationAllowed notBootstrapped {
        require(isTokenSupported(token), "Token not supported");
        ERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        userDeposits[msg.sender][token].totalDeposit += amount;
        userDeposits[msg.sender][token].availableFunds += amount;
        depositsByToken[token] += amount;
        if (!isDepositor[msg.sender]) {
            depositors.push(msg.sender);
            isDepositor[msg.sender] = true;
        }
        emit TokenDepositEvent(msg.sender, token, amount);
    }

    /**
     * @dev Delegates a specified amount of a supported token to an operator. This
     * function is subject to the contract not being paused and the operation being
     * allowed based on the defined timeline.
     *
     * @param operator The address of the operator to delegate to.
     * @param token The address of the ERC20 token being delegated.
     * @param amount The amount of the token to delegate.
     */
    function delegateToOperator(
        address operator,
        address token,
        uint256 amount
    ) external whenNotPaused operationAllowed notBootstrapped {
        require(operators[operator].isRegistered, "Operator not registered");
        require(isTokenSupported(token), "Token not supported");
        require(amount > 0, "Delegation amount must be greater than zero");
        require(
            userDeposits[msg.sender][token].availableFunds >= amount,
            "Insufficient available funds"
        );

        delegations[msg.sender][operator][token] += amount;
        userDeposits[msg.sender][token].availableFunds -= amount;
        totalDelegatedToOperator[operator][token] += amount;

        emit Delegated(msg.sender, operator, token, amount);
    }

    /**
     * @dev Undelegates a specified amount of a token from an operator, effectively
     * withdrawing the delegation. This operation is subject to the contract not
     * being paused and being allowed based on the defined timeline.
     *
     * @param operator The address of the operator from whom to undelegate.
     * @param token The address of the ERC20 token being undelegated.
     * @param amount The amount of the token to undelegate.
     */
    function undelegateFromOperator(
        address operator,
        address token,
        uint256 amount
    ) external whenNotPaused operationAllowed notBootstrapped {
        require(operators[operator].isRegistered, "Operator not registered");
        require(isTokenSupported(token), "Token not supported");
        require(amount > 0, "Undelegation amount must be greater than zero");
        require(
            delegations[msg.sender][operator][token] >= amount,
            "Undelegation amount exceeds delegation"
        );

        delegations[msg.sender][operator][token] -= amount;
        userDeposits[msg.sender][token].availableFunds += amount;
        totalDelegatedToOperator[operator][token] -= amount;

        emit Undelegated(msg.sender, operator, token, amount);
    }

    /**
     * @dev Allows a user to withdraw a specified amount of a supported token from
     * the contract. The operation is subject to the contract not being paused and
     * being allowed based on the defined timeline.
     *
     * @param token The address of the ERC20 token to withdraw.
     * @param amount The amount of the token to withdraw.
     */
    function withdraw(
        address token,
        uint256 amount
    ) external whenNotPaused operationAllowed notBootstrapped {
        require(isTokenSupported(token), "Token not supported");
        require(amount > 0, "Withdrawal amount must be greater than zero");
        require(
            amount <= userDeposits[msg.sender][token].availableFunds,
            "Insufficient available funds"
        );

        ERC20(token).safeTransfer(msg.sender, amount);
        userDeposits[msg.sender][token].totalDeposit -= amount;
        userDeposits[msg.sender][token].availableFunds -= amount;
        depositsByToken[token] -= amount;

        emit Withdrawn(msg.sender, token, amount);
    }

    /**
     * @dev The bootstrapping address can call this function to indicate that the
     * Exocore chain is now bootstrapped. This should be done after at least one
     * block has been produced by the Exocore chain, and the validators collectively
     * send the transaction to this function.
    */
    function markBootstrapped(
    ) external onlyBootstrapAddress notBootstrapped whenNotPaused {
        require(block.timestamp >= exocoreSpawnTime, "Spawn time not reached");
        bootstrapped = true;
        emit Bootstrapped();
    }

     /**
     * @notice Retrieves the total number of supported tokens in the contract.
     *
     * @dev Returns the length of the `supportedTokens` array. This array contains the addresses
     * of all ERC20 tokens that have been added to the contract as supported tokens. This is
     * useful for understanding the scale of token support in the contract and for iterating
     * over the list of all supported tokens when accessing individual token addresses one at a
     * time.
     *
     * @return uint256 The total number of supported tokens.
     */
    function getSupportedTokensCount() public view returns (uint256) {
        return supportedTokens.length;
    }

    /**
     * @notice Retrieves information for a supported token by its index in the storage array.
     * @dev Returns comprehensive details about a token, including its ERC20 attributes and deposit amount.
     * @param index The index of the token in the `supportedTokens` array.
     * @return A `TokenInfo` struct containing the token's name, symbol, address, decimals, total supply, and deposit amount.
     */
    function getSupportedTokenAtIndex(uint256 index) public view returns (TokenInfo memory) {
        require(index < supportedTokens.length, "Index out of bounds");
        address tokenAddress = supportedTokens[index];
        ERC20 token = ERC20(tokenAddress);
        return TokenInfo({
            name: token.name(),
            symbol: token.symbol(),
            tokenAddress: tokenAddress,
            decimals: token.decimals(),
            totalSupply: token.totalSupply(),
            depositAmount: depositsByToken[tokenAddress]
        });
    }

    /**
     * @notice Retrieves the total number of unique depositors who have made deposits into the
     * contract.
     *
     * @dev Returns the count of unique depositor addresses stored in the `depositors` array.
     * This function is useful for understanding the scale of participation in the contract
     * and for iterating over the list of all depositors when accessing individual depositor
     * addresses one at a time.
     *
     * @return uint256 The total number of unique depositors.
     */
    function getDepositorsCount() external view returns (uint256) {
        return depositors.length;
    }

    /**
     * @notice Retrieves the depositor address at a specific index within the list of all
     * depositors.
     *
     * @dev Given an index, returns the address of the depositor located at that index in the
     * `depositors` array. This function is useful for iterating over all depositors when direct
     * access to the dynamic array of addresses is not feasible or desired, especially from
     * external calls that require piecemeal data retrieval.
     *
     * @param index The index within the `depositors` array for which to retrieve the depositor
     * address. Must be less than the total count of depositors returned by `getDepositorCount`.
     *
     * @return address The address of the depositor at the specified index.
     *
     * @dev Reverts if the provided index is out of bounds, ensuring safe access to the array.
     */
    function getDepositorAddressAtIndex(uint256 index) external view returns (address) {
        require(index < depositors.length, "Index out of bounds");
        return depositors[index];
    }

    /**
     * @notice Retrieves the total deposit amount for a specified token and depositor, both identified by their respective indexes.
     * @dev Looks up the depositor and token addresses using their indexes via the Bootstrapping contract, then returns the total deposit amount for that combination.
     * @param dindex The index of the depositor in the Bootstrapping contract's depositor list.
     * @param tindex The index of the token in the Bootstrapping contract's supported token list.
     * @return The total deposit amount of the specified token by the given depositor, identified by indexes.
     */
    function getDepositAmount(uint256 dindex, uint256 tindex) public view returns (uint256) {
        address depositor = Bootstrapping(this).getDepositorAddressAtIndex(dindex);
        address token = Bootstrapping(this).getSupportedTokenAtIndex(tindex).tokenAddress;
        return userDeposits[depositor][token].totalDeposit;
    }

    /**
     * @notice Retrieves the total number of registered operators in the contract.
     *
     * @dev Returns the length of the `registeredOperators` array, which contains the Ethereum
     * addresses of all operators that have been registered in the contract. This function is
     * useful for understanding the scale of operator participation in the contract and for
     * iterating over the list of all registered operators when accessing individual operator
     * addresses one at a time.
     *
     * @return uint256 The total number of registered operators.
     */
    function getOperatorsCount() public view returns (uint256) {
        return registeredOperators.length;
    }

    /**
     * @notice Retrieves the address of an operator at a given index.
     * @dev Returns the address of an operator from the `registeredOperators` array based on the specified index.
     * @param index The index of the operator in the `registeredOperators` array.
     * @return The address of the operator at the specified index.
     */
    function getOperatorAddressAtIndex(
        uint256 index
    ) external view returns (address) {
        require(index < registeredOperators.length, "Index out of bounds");
        return registeredOperators[index];
    }

    /**
     * @notice Retrieves information about a registered operator.
     * @dev Returns the `Operator` struct for the given operator address if they are registered.
     * @param operatorAddress The address of the operator to retrieve information for.
     * @return An `Operator` struct containing details about the operator.
     */
    function getOperatorInfo(
        address operatorAddress
    ) external view returns (Operator memory) {
        require(operators[operatorAddress].isRegistered, "Operator not registered");
        return operators[operatorAddress];
    }

    /**
     * @notice Retrieves the consensus public key of an operator at a given index.
     * @dev Fetches the consensus public key of an operator, using the `Bootstrapping` contract to get the operator's address by index.
     * @param index The index of the operator in the `registeredOperators` array.
     * @return The consensus public key of the operator at the specified index.
     */
    function getOperatorConsensusKeyAtIndex(
        uint256 index
    ) external view returns (bytes32) {
        address operator = Bootstrapping(this).getOperatorAddressAtIndex(index);
        return operators[operator].consensusPublicKey;
    }

    /**
     * @notice Retrieves the delegation state for a specific combination of depositor, operator, and token.
     * @dev Fetches the delegation amount for the given indices representing a depositor, an operator, and a token.
     * @param dindex The index of the depositor in the `depositors` array.
     * @param oindex The index of the operator in the `registeredOperators` array.
     * @param tindex The index of the token in the `supportedTokens` array.
     * @return The amount delegated for the specified combination of depositor, operator, and token.
     */
    function getDelegationStateForIndices(uint256 dindex, uint256 oindex, uint256 tindex)
    public view returns (uint256) {
        Bootstrapping bootstrapping = Bootstrapping(this);
        address depositor = bootstrapping.getDepositorAddressAtIndex(dindex);
        address token = bootstrapping.getSupportedTokenAtIndex(tindex).tokenAddress;
        address operator = bootstrapping.getOperatorAddressAtIndex(oindex);
        return delegations[depositor][operator][token];
    }

    /**
     * @notice Retrieves the total amount delegated to a specific operator for a specified token, both identified by indexes.
     * @dev Fetches the operator and token addresses using their respective indexes from the Bootstrapping contract, then returns the total amount that has been delegated to that operator for the specified token.
     * @param oindex The index of the operator in the Bootstrapping contract's list of operators.
     * @param tindex The index of the token in the Bootstrapping contract's list of supported tokens.
     * @return The total amount of the specified token that has been delegated to the given operator.
     */
    function getTotalDelegatedToOperator(uint256 oindex, uint256 tindex) public view returns (uint256) {
        Bootstrapping bootstrapping = Bootstrapping(this);
        address operator = bootstrapping.getOperatorAddressAtIndex(oindex);
        address token = bootstrapping.getSupportedTokenAtIndex(tindex).tokenAddress;
        return totalDelegatedToOperator[operator][token];
    }
}
