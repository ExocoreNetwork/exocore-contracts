// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ExocoreBtcGatewayStorage
 * @dev This contract manages the storage for the Exocore-Bitcoin gateway
 */
contract ExocoreBtcGatewayStorage {

    /**
     * @notice Enum to represent the type of supported token
     * @dev Each field should be matched with the corresponding field of ClientChainID
     */
    enum Token {
        None, // 0: Invalid/uninitialized token
        BTC // 1: Bitcoin token, matches with ClientChainID.Bitcoin

    }

    /**
     * @notice Enum to represent the supported client chain ID
     * @dev Each field should be matched with the corresponding field of Token
     */
    enum ClientChainID {
        None, // 0: Invalid/uninitialized chain
        Bitcoin // 1: Bitcoin chain, matches with Token.BTC

    }

    /**
     * @dev Enum to represent the status of a transaction
     */
    enum TxStatus {
        NotStarted, // 0: Default state - transaction hasn't started collecting proofs
        Pending, // 1: Currently collecting witness proofs
        Expired // 2: Failed due to timeout, but can be retried

    }

    /**
     * @dev Enum to represent the WithdrawType
     */
    enum WithdrawType {
        Undefined,
        WithdrawPrincipal,
        WithdrawReward
    }

    /**
     * @dev Struct to store transaction information
     */
    struct TxInfo {
        bool processed;
        uint256 timestamp;
    }

    /**
     * @dev Struct to store interchain message information
     */
    struct StakeMsg {
        ClientChainID chainId;
        bytes srcAddress; // the address of the depositor on the source chain
        address exocoreAddress; // the address of the depositor on the Exocore chain
        string operator; // the operator to delegate to, would only deposit to exocore address if operator is empty
        uint256 amount; // deposit amount
        uint64 nonce;
        bytes txTag; // lowercase(txid-vout)
    }

    /**
     * @dev Struct to store proof information
     */
    struct Proof {
        address witness;
        StakeMsg message;
        uint256 timestamp;
        bytes signature;
    }

    /**
     * @dev Struct to store transaction information
     */
    struct Transaction {
        TxStatus status;
        uint256 proofCount;
        uint256 expiryTime;
        mapping(address => uint256) witnessTime;
        StakeMsg stakeMsg;
    }

    /**
     * @dev Struct for peg-out requests
     */
    struct PegOutRequest {
        ClientChainID chainId;
        uint64 nonce;
        address requester;
        bytes clientChainAddress;
        uint256 amount;
        WithdrawType withdrawType;
        uint256 timestamp;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Constants                                 */
    /* -------------------------------------------------------------------------- */
    // chain id from layerzero, virtual for bitcoin since it's not yet a layerzero chain
    string public constant BITCOIN_NAME = "Bitcoin";
    string public constant BITCOIN_METADATA = "Bitcoin";
    string public constant BITCOIN_SIGNATURE_SCHEME = "ECDSA";
    uint8 public constant STAKER_ACCOUNT_LENGTH = 20;

    // virtual token address and token, shared for tokens supported by the gateway
    address public constant VIRTUAL_TOKEN_ADDRESS = 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB;
    bytes public constant VIRTUAL_TOKEN = abi.encodePacked(bytes32(bytes20(VIRTUAL_TOKEN_ADDRESS)));

    uint8 public constant BTC_DECIMALS = 8;
    string public constant BTC_NAME = "BTC";
    string public constant BTC_METADATA = "BTC";
    string public constant BTC_ORACLE_INFO = "BTC,BITCOIN,8";

    address public constant EXOCORE_WITNESS = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    uint256 public constant REQUIRED_PROOFS = 2;
    uint256 public constant PROOF_TIMEOUT = 1 days;
    uint256 public bridgeFee; // Fee percentage (in basis points, e.g., 100 = 1%)

    /**
     * @dev Mapping to store transaction information, key is the message hash
     */
    mapping(bytes32 => Transaction) public transactions;

    /**
     * @dev Mapping to store processed Bitcoin transactions
     */
    mapping(bytes => TxInfo) public processedBtcTxs;

    /**
     * @dev Mapping to store peg-out requests, key is the nonce
     */
    mapping(uint64 => PegOutRequest) public pegOutRequests;

    /**
     * @dev Mapping to store authorized witnesses
     */
    mapping(address => bool) public authorizedWitnesses;

    /**
     * @dev Maps client chain addresses to their registered Exocore addresses
     * @dev Key1: Client chain ID (Bitcoin, etc.)
     * @dev Key2: Client chain address in bytes
     * @dev Value: Registered Exocore address
     */
    mapping(ClientChainID => mapping(bytes => address)) public inboundRegistry;

    /**
     * @dev Maps Exocore addresses to their registered client chain addresses
     * @dev Key1: Client chain ID (Bitcoin, etc.)
     * @dev Key2: Exocore address
     * @dev Value: Registered client chain address in bytes
     */
    mapping(ClientChainID => mapping(address => bytes)) public outboundRegistry;

    /**
     * @dev Mapping to store inbound nonce for each chain
     */
    mapping(ClientChainID => uint64) public inboundNonce;

    /**
     * @notice Mapping to store outbound nonce for each chain
     */
    mapping(ClientChainID => uint64) public outboundNonce;

    /**
     * @notice Mapping to store peg-out nonce for each chain
     */
    mapping(ClientChainID => uint64) public pegOutNonce;

    /**
     * @notice Mapping to store delegation nonce for each chain
     * @dev The nonce is incremented for each delegate/undelegate operation
     * @dev The nonce is provided to the precompile as operation id
     */
    mapping(ClientChainID => uint64) public delegationNonce;

    uint256[40] private __gap;

    // Events
    /**
     * @dev Emitted when a deposit is completed
     * @param srcChainId The source chain ID
     * @param txTag The txid + vout-index
     * @param depositorExoAddr The depositor's Exocore address
     * @param depositorClientChainAddr The depositor's client chain address
     * @param amount The amount deposited
     * @param updatedBalance The updated balance after deposit
     */
    event DepositCompleted(
        ClientChainID indexed srcChainId,
        bytes txTag,
        address indexed depositorExoAddr,
        bytes depositorClientChainAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a principal withdrawal is requested
     * @param requestId The unique identifier for the withdrawal request
     * @param srcChainId The source chain ID
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param withdrawerClientChainAddr The withdrawer's client chain address
     * @param amount The amount to withdraw
     * @param updatedBalance The updated balance after withdrawal request
     */
    event WithdrawPrincipalRequested(
        ClientChainID indexed srcChainId,
        uint64 indexed requestId,
        address indexed withdrawerExoAddr,
        bytes withdrawerClientChainAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a reward withdrawal is requested
     * @param requestId The unique identifier for the withdrawal request
     * @param srcChainId The source chain ID
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param withdrawerClientChainAddr The withdrawer's client chain address
     * @param amount The amount to withdraw
     * @param updatedBalance The updated balance after withdrawal request
     */
    event WithdrawRewardRequested(
        ClientChainID indexed srcChainId,
        uint64 indexed requestId,
        address indexed withdrawerExoAddr,
        bytes withdrawerClientChainAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a principal withdrawal is completed
     * @param srcChainId The source chain ID
     * @param requestId The unique identifier for the withdrawal request
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param withdrawerClientChainAddr The withdrawer's client chain address
     * @param amount The amount withdrawn
     * @param updatedBalance The updated balance after withdrawal
     */
    event WithdrawPrincipalCompleted(
        ClientChainID indexed srcChainId,
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        bytes withdrawerClientChainAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a reward withdrawal is completed
     * @param srcChainId The source chain ID
     * @param requestId The unique identifier for the withdrawal request
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param withdrawerClientChainAddr The withdrawer's client chain address
     * @param amount The amount withdrawn
     * @param updatedBalance The updated balance after withdrawal
     */
    event WithdrawRewardCompleted(
        ClientChainID indexed srcChainId,
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        bytes withdrawerClientChainAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a delegation is completed
     * @param clientChainId The LayerZero chain ID of the client chain
     * @param exoDelegator The delegator's Exocore address
     * @param operator The operator's address
     * @param amount The amount delegated
     */
    event DelegationCompleted(
        ClientChainID indexed clientChainId, address indexed exoDelegator, string operator, uint256 amount
    );

    /**
     * @dev Emitted when a delegation fails for a stake message
     * @param clientChainId The LayerZero chain ID of the client chain
     * @param exoDelegator The delegator's Exocore address
     * @param operator The operator's address
     * @param amount The amount delegated
     */
    event DelegationFailedForStake(
        ClientChainID indexed clientChainId, address indexed exoDelegator, string operator, uint256 amount
    );

    /**
     * @dev Emitted when an undelegation is completed
     * @param clientChainId The LayerZero chain ID of the client chain
     * @param exoDelegator The delegator's Exocore address
     * @param operator The operator's address
     * @param amount The amount undelegated
     */
    event UndelegationCompleted(
        ClientChainID indexed clientChainId, address indexed exoDelegator, string operator, uint256 amount
    );

    /**
     * @dev Emitted when an address is registered
     * @param chainId The LayerZero chain ID of the client chain
     * @param depositor The depositor's address
     * @param exocoreAddress The corresponding Exocore address
     */
    event AddressRegistered(ClientChainID indexed chainId, bytes depositor, address indexed exocoreAddress);

    /**
     * @dev Emitted when a new witness is added
     * @param witness The address of the added witness
     */
    event WitnessAdded(address indexed witness);

    /**
     * @dev Emitted when a witness is removed
     * @param witness The address of the removed witness
     */
    event WitnessRemoved(address indexed witness);

    /**
     * @dev Emitted when a proof is submitted
     * @param messageHash The hash of the stake message
     * @param witness The address of the witness submitting the proof
     * @param message The stake message associated with the proof
     */
    event ProofSubmitted(bytes32 indexed messageHash, address indexed witness, StakeMsg message);

    /**
     * @dev Emitted when a deposit is processed
     * @param txTag The txid + vout-index
     * @param recipient The address of the recipient
     * @param amount The amount processed
     */
    event DepositProcessed(bytes txTag, address indexed recipient, uint256 amount);

    /**
     * @dev Emitted when a transaction expires
     * @param txid The message hash of the expired transaction
     */
    event TransactionExpired(bytes32 txid);

    /**
     * @dev Emitted when a peg-out transaction expires
     * @param requestId The unique identifier of the expired peg-out request
     */
    event PegOutTransactionExpired(bytes32 requestId);

    /**
     * @dev Emitted when the bridge fee is updated
     * @param newFee The new bridge fee
     */
    event BridgeFeeUpdated(uint256 newFee);

    /**
     * @dev Emitted when the deposit limit is updated
     * @param newLimit The new deposit limit
     */
    event DepositLimitUpdated(uint256 newLimit);

    /**
     * @dev Emitted when the withdrawal limit is updated
     * @param newLimit The new withdrawal limit
     */
    event WithdrawalLimitUpdated(uint256 newLimit);

    /**
     * @dev Emitted when a peg-out is processed
     * @param requestId The unique identifier of the processed peg-out request
     */
    event PegOutProcessed(uint64 indexed requestId);

    /**
     * @dev Emitted when a peg-out request status is updated
     * @param requestId The unique identifier of the peg-out request
     * @param newStatus The new status of the peg-out request
     */
    event PegOutRequestStatusUpdated(bytes32 indexed requestId, TxStatus newStatus);

    /// @notice Emitted upon the registration of a new client chain.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    event ClientChainRegistered(uint32 clientChainId);

    /// @notice Emitted upon the update of a client chain.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    event ClientChainUpdated(uint32 clientChainId);

    /// @notice Emitted when a token is added to the whitelist.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    /// @param token The address of the token.
    event WhitelistTokenAdded(uint32 clientChainId, address indexed token);

    /// @notice Emitted when a token is updated in the whitelist.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    /// @param token The address of the token.
    event WhitelistTokenUpdated(uint32 clientChainId, address indexed token);

    // Errors
    /**
     * @dev Thrown when an unauthorized witness attempts an action
     */
    error UnauthorizedWitness();

    /**
     * @dev Thrown when registering a client chain to Exocore fails
     * @param clientChainId The ID of the client chain that failed to register
     */
    error RegisterClientChainToExocoreFailed(uint32 clientChainId);

    /**
     * @dev Thrown when a zero address is provided where it's not allowed
     */
    error ZeroAddressNotAllowed();

    /**
     * @dev Thrown when attempting to process a Bitcoin transaction that has already been processed
     */
    error BtcTxAlreadyProcessed();

    /**
     * @dev Thrown when an address is not registered
     */
    error AddressNotRegistered();

    /**
     * @dev Thrown when trying to process a request with an invalid status
     * @param requestId The ID of the request with the invalid status
     */
    error InvalidRequestStatus(bytes32 requestId);

    /**
     * @dev Thrown when the requested peg-out does not exist
     * @param requestId The ID of the non-existent request
     */
    error RequestNotFound(uint64 requestId);

    /**
     * @dev Thrown when attempting to create a request that already exists
     * @param requestId The ID of the existing request
     */
    error RequestAlreadyExists(uint64 requestId);

    /**
     * @dev Thrown when a deposit operation fails
     * @param btcTxTag The Bitcoin transaction tag of the failed deposit
     */
    error DepositFailed(bytes btcTxTag);

    /**
     * @dev Thrown when a principal withdrawal operation fails
     */
    error WithdrawPrincipalFailed();

    /**
     * @dev Thrown when a reward withdrawal operation fails
     */
    error WithdrawRewardFailed();

    /**
     * @dev Thrown when a delegation operation fails, not when processing a stake message
     */
    error DelegationFailed();

    /**
     * @dev Thrown when an undelegation operation fails
     */
    error UndelegationFailed();

    /**
     * @dev Thrown when an Ether transfer fails
     */
    error EtherTransferFailed();

    /**
     * @dev Thrown when an invalid signature is provided
     */
    error InvalidSignature();

    /**
     * @dev Thrown when an unexpected inbound nonce is encountered
     * @param expectedNonce The expected nonce
     * @param actualNonce The actual nonce received
     */
    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);

    error InvalidTokenType();
    error InvalidClientChainId();

    /**
     * @dev Modifier to check if an amount is valid
     * @param amount The amount to check
     */
    modifier isValidAmount(uint256 amount) {
        require(amount > 0, "ExocoreBtcGatewayStorage: amount should be greater than zero");
        _;
    }

    modifier isValidToken(Token token) {
        require(token != Token.None, "ExocoreBtcGatewayStorage: Invalid token");
        _;
    }

    modifier isRegistered(Token token, address exocoreAddress) {
        require(
            outboundRegistry[ClientChainID(uint8(token))][exocoreAddress].length > 0,
            "ExocoreBtcGatewayStorage: Address not registered"
        );
        _;
    }

    /**
     * @dev Internal function to verify and update the inbound bytes nonce
     * @param srcChainId The source chain ID
     * @param nonce The nonce to verify
     */
    function _verifyInboundNonce(ClientChainID srcChainId, uint64 nonce) internal view {
        if (nonce != inboundNonce[srcChainId] + 1) {
            revert UnexpectedInboundNonce(inboundNonce[srcChainId] + 1, nonce);
        }
    }

}
