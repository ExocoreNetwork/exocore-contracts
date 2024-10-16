// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ExocoreBtcGatewayStorage
 * @dev This contract manages the storage for the Exocore-Bitcoin gateway
 */
contract ExocoreBtcGatewayStorage {

    /**
     * @dev Enum to represent the status of a transaction
     */
    enum TxStatus {
        Pending,
        Processed,
        Expired
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
    struct InterchainMsg {
        uint32 srcChainID;
        uint32 dstChainID;
        bytes srcAddress;
        bytes dstAddress;
        address token; // btc virtual token
        uint256 amount; // btc deposit amount
        uint64 nonce;
        bytes txTag; // btc lowercase(txid-vout)
        bytes payload;
    }

    /**
     * @dev Struct to store proof information
     */
    struct Proof {
        address witness;
        InterchainMsg message;
        uint256 timestamp;
        bytes signature;
    }

    /**
     * @dev Struct to store transaction information
     */
    struct Transaction {
        TxStatus status;
        uint256 amount;
        address recipient;
        uint256 expiryTime;
        uint256 proofCount;
        mapping(address => bool) hasWitnessed;
    }

    /**
     * @dev Struct for peg-out requests
     */
    struct PegOutRequest {
        address token;
        address requester;
        bytes btcAddress;
        uint256 amount;
        WithdrawType withdrawType;
        TxStatus status;
        uint256 timestamp;
    }

    // Constants
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
    mapping(bytes => bytes) public btcToExocoreAddress;

    /**
     * @dev Mapping to store Exocore to Bitcoin address mappings
     */
    mapping(bytes => bytes) public exocoreToBtcAddress;

    /**
     * @dev Mapping to store whitelisted tokens
     */
    mapping(address => bool) public isWhitelistedToken;

    /**
     * @dev Mapping to store inbound bytes nonce for each chain and sender
     */
    mapping(uint32 => mapping(bytes => uint64)) public inboundBytesNonce;

    // Events
    /**
     * @dev Emitted when a deposit is completed
     * @param btcTxTag The Bitcoin transaction tag
     * @param depositorExoAddr The depositor's Exocore address
     * @param token The token address
     * @param depositorBtcAddr The depositor's Bitcoin address
     * @param amount The amount deposited
     * @param updatedBalance The updated balance after deposit
     */
    event DepositCompleted(
        bytes btcTxTag,
        bytes depositorExoAddr,
        address indexed token,
        bytes depositorBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a principal withdrawal is requested
     * @param requestId The unique identifier for the withdrawal request
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param token The token address
     * @param withdrawerBtcAddr The withdrawer's Bitcoin address
     * @param amount The amount to withdraw
     * @param updatedBalance The updated balance after withdrawal request
     */
    event WithdrawPrincipalRequested(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address indexed token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a reward withdrawal is requested
     * @param requestId The unique identifier for the withdrawal request
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param token The token address
     * @param withdrawerBtcAddr The withdrawer's Bitcoin address
     * @param amount The amount to withdraw
     * @param updatedBalance The updated balance after withdrawal request
     */
    event WithdrawRewardRequested(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address indexed token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a principal withdrawal is completed
     * @param requestId The unique identifier for the withdrawal request
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param token The token address
     * @param withdrawerBtcAddr The withdrawer's Bitcoin address
     * @param amount The amount withdrawn
     * @param updatedBalance The updated balance after withdrawal
     */
    event WithdrawPrincipalCompleted(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address indexed token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a reward withdrawal is completed
     * @param requestId The unique identifier for the withdrawal request
     * @param withdrawerExoAddr The withdrawer's Exocore address
     * @param token The token address
     * @param withdrawerBtcAddr The withdrawer's Bitcoin address
     * @param amount The amount withdrawn
     * @param updatedBalance The updated balance after withdrawal
     */
    event WithdrawRewardCompleted(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address indexed token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );

    /**
     * @dev Emitted when a delegation is completed
     * @param token The token address
     * @param delegator The delegator's address
     * @param operator The operator's address
     * @param amount The amount delegated
     */
    event DelegationCompleted(address token, bytes delegator, bytes operator, uint256 amount);

    /**
     * @dev Emitted when an undelegation is completed
     * @param token The token address
     * @param delegator The delegator's address
     * @param operator The operator's address
     * @param amount The amount undelegated
     */
    event UndelegationCompleted(address token, bytes delegator, bytes operator, uint256 amount);

    /**
     * @dev Emitted when a deposit and delegation is completed
     * @param token The token address
     * @param depositor The depositor's address
     * @param operator The operator's address
     * @param amount The amount deposited and delegated
     * @param updatedBalance The updated balance after the operation
     */
    event DepositAndDelegationCompleted(
        address token, bytes depositor, bytes operator, uint256 amount, uint256 updatedBalance
    );

    /**
     * @dev Emitted when an address is registered
     * @param depositor The depositor's address
     * @param exocoreAddress The corresponding Exocore address
     */
    event AddressRegistered(bytes depositor, bytes exocoreAddress);

    /**
     * @dev Emitted when an Exocore precompile error occurs
     * @param precompileAddress The address of the precompile that caused the error
     */
    event ExocorePrecompileError(address precompileAddress);

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
     * @param btcTxTag The Bitcoin transaction tag
     * @param witness The address of the witness submitting the proof
     * @param message The interchain message associated with the proof
     */
    event ProofSubmitted(bytes btcTxTag, address indexed witness, InterchainMsg message);

    /**
     * @dev Emitted when a deposit is processed
     * @param btcTxTag The Bitcoin transaction tag
     * @param recipient The address of the recipient
     * @param amount The amount processed
     */
    event DepositProcessed(bytes btcTxTag, address indexed recipient, uint256 amount);

    /**
     * @dev Emitted when a transaction expires
     * @param btcTxTag The Bitcoin transaction tag of the expired transaction
     */
    event TransactionExpired(bytes btcTxTag);

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

    /**
     * @dev Modifier to check if a token is whitelisted
     * @param token The address of the token to check
     */
    modifier isTokenWhitelisted(address token) {
        require(isWhitelistedToken[token], "ExocoreBtcGatewayStorage: token is not whitelisted");
        _;
    }

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

    uint256[40] private __gap;

}
