// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ExocoreBtcGatewayStorage {

    // Enum to represent the status of a transaction
    enum TxStatus {
        Pending,
        Processed,
        Expired
    }

    // Enum to represent the WithdrawType
    enum WithdrawType {
        Undefined,
        WithdrawPrincipal,
        WithdrawReward
    }

    struct TxInfo {
        bool processed;
        uint256 timestamp;
    }

    struct InterchainMsg {
        uint32 srcChainID;
        uint32 dstChainID;
        bytes srcAddress;
        bytes dstAddress;
        address token; // btc virtual token
        uint256 amount; //btc deposit amount
        uint64 nonce;
        bytes txTag; //btc lowercase(txid-vout)
        bytes payload;
    }

    // Struct to store proof information
    struct Proof {
        address witness;
        InterchainMsg message;
        uint256 timestamp;
        bytes signature;
    }

    // Struct to store transaction information
    struct Transaction {
        TxStatus status;
        uint256 amount;
        address recipient;
        uint256 expiryTime;
        uint256 proofCount;
        mapping(address => bool) hasWitnessed;
    }

    // Struct for peg-out requests
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

    // Mapping to store proofs submitted by witnesses
    mapping(bytes32 => Proof[]) public proofs;

    // Mapping to store transaction information
    mapping(bytes32 => Transaction) public transactions;
    mapping(bytes => TxInfo) public processedBtcTxs;

    // Mapping to store peg-out requests
    mapping(bytes32 => PegOutRequest) public pegOutRequests;

    // Mapping to store authorized witnesses
    mapping(address => bool) public authorizedWitnesses;
    mapping(bytes => bytes) public btcToExocoreAddress;
    mapping(bytes => bytes) public exocoreToBtcAddress;

    mapping(address token => bool whitelisted) public isWhitelistedToken;
    mapping(uint32 eid => mapping(bytes sender => uint64 nonce)) public inboundBytesNonce;

    event DepositCompleted(
        bytes indexed btcTxTag,
        bytes indexed depositorExoAddr,
        address token,
        bytes depositorBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );
    event WithdrawPrincipalRequested(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );
    event WithdrawRewardRequested(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );
    event WithdrawPrincipalCompleted(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );
    event WithdrawRewardCompleted(
        bytes32 indexed requestId,
        address indexed withdrawerExoAddr,
        address token,
        bytes withdrawerBtcAddr,
        uint256 amount,
        uint256 updatedBalance
    );
    event DelegationCompleted(address token, bytes delegator, bytes operator, uint256 amount);
    event UndelegationCompleted(address token, bytes delegator, bytes operator, uint256 amount);
    event DepositAndDelegationCompleted(
        address token, bytes depositor, bytes operator, uint256 amount, uint256 updatedBalance
    );
    event AddressRegistered(bytes depositor, bytes exocoreAddress);
    event ExocorePrecompileError(address precompileAddress);
    event WitnessAdded(address indexed witness);
    event WitnessRemoved(address indexed witness);
    event ProofSubmitted(bytes32 indexed btcTxTag, address indexed witness, InterchainMsg message);
    event DepositProcessed(bytes32 indexed btcTxTag, address indexed recipient, uint256 amount);
    event TransactionExpired(bytes32 indexed btcTxTag);
    event BridgeFeeUpdated(uint256 newFee);
    event DepositLimitUpdated(uint256 newLimit);
    event WithdrawalLimitUpdated(uint256 newLimit);
    event PegOutProcessed(bytes32 indexed requestId, bytes32 btcTxTag);

    error UnauthorizedWitness();
    error RegisterClientChainToExocoreFailed(uint32 clientChainId);
    error ZeroAddressNotAllowed();
    error BtcTxAlreadyProcessed();
    error BtcAddressNotRegistered();
    error DepositFailed(bytes btcTxTag);
    error WithdrawPrincipalFailed();
    error WithdrawRewardFailed();
    error DelegationFailed();
    error UndelegationFailed();
    error EtherTransferFailed();
    error InvalidSignature();

    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);

    modifier isTokenWhitelisted(address token) {
        require(isWhitelistedToken[token], "ExocoreBtcGatewayStorage: token is not whitelisted");
        _;
    }

    modifier isValidAmount(uint256 amount) {
        require(amount > 0, "ExocoreBtcGatewayStorage: amount should be greater than zero");
        _;
    }

    function _verifyAndUpdateBytesNonce(uint32 srcChainId, bytes memory srcAddress, uint64 nonce) internal {
        uint64 expectedNonce = inboundBytesNonce[srcChainId][srcAddress] + 1;
        if (nonce != expectedNonce) {
            revert UnexpectedInboundNonce(expectedNonce, nonce);
        }
        inboundBytesNonce[srcChainId][srcAddress] = nonce;
    }

    uint256[40] private __gap;

}
