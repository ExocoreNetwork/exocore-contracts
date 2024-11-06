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
        BTC
    }

    /**
     * @notice Enum to represent the supported client chain ID
     * @dev Each field should be matched with the corresponding field of TokenType
     */
    enum ClientChain {
        Bitcoin
    }

    /**
     * @dev Enum to represent the status of a transaction
     */
    enum TxStatus {
        NotStarted,    // 0: Default state - transaction hasn't started collecting proofs
        Pending,       // 1: Currently collecting witness proofs
        Processed,     // 2: Successfully processed
        Expired        // 3: Failed due to timeout, but can be retried
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
        ClientChain clientChain;
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
        ClientChain clientChain;
        uint256 amount;
        bytes srcAddress;
        address recipient;
        uint256 expiryTime;
        uint256 proofCount;
        mapping(address => uint256) witnessTime;
    }

    /**
     * @dev Struct for peg-out requests
     */
    struct PegOutRequest {
        ClientChain clientChain;
        address requester;
        bytes clientChainAddress;
        uint256 amount;
        WithdrawType withdrawType;
        TxStatus status;
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

    // Mappings
    /**
     * @dev Mapping to store proofs submitted by witnesses
     */
    mapping(bytes => Proof[]) public proofs;

    /**
     * @dev Mapping to store transaction information
     */
    mapping(bytes => Transaction) public transactions;

    /**
     * @dev Mapping to store processed Bitcoin transactions
     */
    mapping(bytes => TxInfo) public processedBtcTxs;

    /**
     * @dev Mapping to store peg-out requests
     */
    mapping(bytes32 => PegOutRequest) public pegOutRequests;

    /**
     * @dev Mapping to store authorized witnesses
     */
    mapping(address => bool) public authorizedWitnesses;

    /**
     * @dev Mapping to store Bitcoin to Exocore address mappings
     */
    mapping(bytes => address) public btcToExocoreAddress;

    /**
     * @dev Mapping to store Exocore to Bitcoin address mappings
     */
    mapping(address => bytes) public exocoreToBtcAddress;

    /**
     * @dev Mapping to store inbound bytes nonce for each chain and sender
     */
    mapping(uint32 => mapping(bytes => uint64)) public inboundBytesNonce;

    /**
     * @notice Mapping to store delegation nonce for each chain and delegator
     * @dev The nonce is incremented for each delegate/undelegate operation
     * @dev The nonce is provided to the precompile as operation id
     */
    mapping(uint32 => mapping(address => uint64)) public delegationNonce;

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
        uint32 indexed srcChainId,
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
        uint32 indexed srcChainId,
        bytes32 indexed requestId,
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
        uint32 indexed srcChainId,
        bytes32 indexed requestId,
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
        uint32 indexed srcChainId,
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
        uint32 indexed srcChainId,
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
    event DelegationCompleted(uint32 clientChainId, address exoDelegator, string operator, uint256 amount);

    /**
     * @dev Emitted when an undelegation is completed
     * @param clientChainId The LayerZero chain ID of the client chain
     * @param exoDelegator The delegator's Exocore address
     * @param operator The operator's address
     * @param amount The amount undelegated
     */
    event UndelegationCompleted(uint32 clientChainId, address exoDelegator, string operator, uint256 amount);

    /**
     * @dev Emitted when a deposit and delegation is completed
     * @param clientChainId The LayerZero chain ID of the client chain
     * @param exoDepositor The depositor's Exocore address
     * @param operator The operator's address
     * @param amount The amount deposited and delegated
     * @param updatedBalance The updated balance after the operation
     */
    event DepositAndDelegationCompleted(uint32 clientChainId, address exoDepositor, string operator, uint256 amount, uint256 updatedBalance);

    /**
     * @dev Emitted when an address is registered
     * @param depositor The depositor's address
     * @param exocoreAddress The corresponding Exocore address
     */
    event AddressRegistered(bytes depositor, address indexed exocoreAddress);

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
     * @param txTag The txid + vout-index
     * @param witness The address of the witness submitting the proof
     * @param message The interchain message associated with the proof
     */
    event ProofSubmitted(bytes txTag, address indexed witness, StakeMsg message);

    /**
     * @dev Emitted when a deposit is processed
     * @param txTag The txid + vout-index
     * @param recipient The address of the recipient
     * @param amount The amount processed
     */
    event DepositProcessed(bytes txTag, address indexed recipient, uint256 amount);

    /**
     * @dev Emitted when a transaction expires
     * @param txTag The txid + vout-index of the expired transaction
     */
    event TransactionExpired(bytes txTag);

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
     * @param btcTxTag The Bitcoin transaction tag associated with the peg-out
     */
    event PegOutProcessed(bytes32 indexed requestId, bytes32 btcTxTag);

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
     * @dev Thrown when a Bitcoin address is not registered
     */
    error BtcAddressNotRegistered();

    /**
     * @dev Thrown when trying to process a request with an invalid status
     * @param requestId The ID of the request with the invalid status
     */
    error InvalidRequestStatus(bytes32 requestId);

    /**
     * @dev Thrown when the requested peg-out does not exist
     * @param requestId The ID of the non-existent request
     */
    error RequestNotFound(bytes32 requestId);

    /**
     * @dev Thrown when attempting to create a request that already exists
     * @param requestId The ID of the existing request
     */
    error RequestAlreadyExists(bytes32 requestId);

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
     * @dev Thrown when a delegation operation fails
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

    /**
     * @dev Internal function to verify and update the inbound bytes nonce
     * @param srcChainId The source chain ID
     * @param srcAddress The source address
     * @param nonce The nonce to verify
     */
    function _verifyAndUpdateBytesNonce(uint32 srcChainId, bytes memory srcAddress, uint64 nonce) internal {
        uint64 expectedNonce = inboundBytesNonce[srcChainId][srcAddress] + 1;
        if (nonce != expectedNonce) {
            revert UnexpectedInboundNonce(expectedNonce, nonce);
        }
        inboundBytesNonce[srcChainId][srcAddress] = nonce;
    }

    function getChainIdByToken(Token token) public pure returns (uint32) {
        return uint32(uint8(token)) + 1;
    }

    function getChainId(ClientChain clientChain) public pure returns (uint32) {
        return uint32(uint8(clientChain)) + 1;
    }
}
