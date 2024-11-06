// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Errors} from "../libraries/Errors.sol";
import {ExocoreBytes} from "../libraries/ExocoreBytes.sol";

import {ASSETS_CONTRACT} from "../interfaces/precompiles/IAssets.sol";
import {DELEGATION_CONTRACT} from "../interfaces/precompiles/IDelegation.sol";
import {REWARD_CONTRACT} from "../interfaces/precompiles/IReward.sol";
import {SignatureVerifier} from "../libraries/SignatureVerifier.sol";
import {ExocoreBtcGatewayStorage} from "../storage/ExocoreBtcGatewayStorage.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
// import "forge-std/console.sol";
/**
 * @title ExocoreBtcGateway
 * @dev This contract manages the gateway between Bitcoin and the Exocore system.
 * It handles deposits, delegations, withdrawals, and peg-out requests for BTC.
 */

contract ExocoreBtcGateway is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    ExocoreBtcGatewayStorage
{
    using ExocoreBytes for address;

    /**
     * @dev Modifier to restrict access to authorized witnesses only.
     */
    modifier onlyAuthorizedWitness() {
        if (!_isAuthorizedWitness(msg.sender)) {
            revert UnauthorizedWitness();
        }
        _;
    }

    /**
     * @notice Pauses the contract.
     * @dev Can only be called by the contract owner.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpauses the contract.
     * @dev Can only be called by the contract owner.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Constructor to initialize the contract with the client chain ID.
     * @dev Sets up initial configuration for testing purposes.
     */
    constructor() {
        authorizedWitnesses[EXOCORE_WITNESS] = true;
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with the Exocore witness address.
     * @param _witness The address of the Exocore witness .
     */
    function initialize(address _witness) external initializer {
        addWitness(_witness);
        __Pausable_init_unchained();
    }

    /**
     * @notice Activates token staking by registering or updating the chain and token with the Exocore system.
     */
    function activateStakingForClientChain(ClientChain clientChain_) external {
        if (clientChain_ == ClientChain.Bitcoin) {
            _registerOrUpdateClientChain(
                getChainId(clientChain_),
                STAKER_ACCOUNT_LENGTH,
                BITCOIN_NAME,
                BITCOIN_METADATA,
                BITCOIN_SIGNATURE_SCHEME
            );
            _registerOrUpdateToken(
                getChainId(clientChain_),
                VIRTUAL_TOKEN,
                BTC_DECIMALS,
                BTC_NAME,
                BTC_METADATA,
                BTC_ORACLE_INFO
            );
        } else {
            revert InvalidTokenType();
        }
    }

    /**
     * @notice Adds a new authorized witness.
     * @param _witness The address of the witness to be added.
     * @dev Can only be called by the contract owner.
     */
    function addWitness(address _witness) public onlyOwner {
        if (_witness == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        require(!authorizedWitnesses[_witness], "Witness already authorized");
        authorizedWitnesses[_witness] = true;
        emit WitnessAdded(_witness);
    }

    /**
     * @notice Removes an authorized witness.
     * @param _witness The address of the witness to be removed.
     * @dev Can only be called by the contract owner.
     */
    function removeWitness(address _witness) external onlyOwner {
        require(authorizedWitnesses[_witness], "Witness not authorized");
        authorizedWitnesses[_witness] = false;
        emit WitnessRemoved(_witness);
    }

    /**
     * @notice Updates the bridge fee.
     * @param _newFee The new fee to be set (in basis points, max 1000 or 10%).
     * @dev Can only be called by the contract owner.
     */
    function updateBridgeFee(uint256 _newFee) external onlyOwner {
        require(_newFee <= 1000, "Fee cannot exceed 10%"); // Max fee of 10%
        bridgeFee = _newFee;
        emit BridgeFeeUpdated(_newFee);
    }

    /**
     * @notice Checks and updates expired transactions.
     * @param _txTags An array of transaction tags to check.
     */
    function checkExpiredTransactions(bytes[] calldata _txTags) external {
        for (uint256 i = 0; i < _txTags.length; i++) {
            _revokeTxIfExpired(_txTags[i]);
        }
    }

    /**
     * @notice Registers a BTC address with an Exocore address.
     * @param depositor The BTC address to register.
     * @param exocoreAddress The corresponding Exocore address.
     * @dev Can only be called by an authorized witness.
     */
    function registerAddress(bytes calldata depositor, address exocoreAddress) external onlyAuthorizedWitness {
        require(depositor.length > 0 && exocoreAddress != address(0), "Invalid address");
        require(btcToExocoreAddress[depositor] != address(0), "Depositor address already registered");
        require(exocoreToBtcAddress[exocoreAddress].length == 0, "Exocore address already registered");

        btcToExocoreAddress[depositor] = exocoreAddress;
        exocoreToBtcAddress[exocoreAddress] = depositor;

        emit AddressRegistered(depositor, exocoreAddress);
    }

    /**
     * @notice Submits a proof for a transaction.
     * @param _message The interchain message.
     * @param _signature The signature of the message.
     */
    function submitProof(StakeMsg calldata _message, bytes calldata _signature)
        external
        nonReentrant
        whenNotPaused
    {
        // Verify the signature
        if (processedBtcTxs[_message.txTag].processed) {
            revert BtcTxAlreadyProcessed();
        }

        // we should revoke the tx by setting it as expired if it has expired
        _revokeTxIfExpired(_message.txTag);

        // Verify nonce
        _verifyAndUpdateBytesNonce(getChainId(_message.clientChain), _message.srcAddress, _message.nonce);

        // Verify signature
        _verifySignature(_message, _signature);

        bytes memory txTag = _message.txTag;
        Transaction storage txn = transactions[txTag];

        if (txn.status == TxStatus.Pending) {
            // if the witness has already submitted proof at or after the start of the proof window, they cannot submit again
            if (txn.witnessTime[msg.sender] >= txn.expiryTime - PROOF_TIMEOUT) {
                revert Errors.WitnessAlreadySubmittedProof();
            }
            txn.witnessTime[msg.sender] = block.timestamp;
            txn.proofCount++;
        } else {
            txn.status = TxStatus.Pending;
            txn.clientChain = _message.clientChain;
            txn.amount = _message.amount;
            txn.recipient = address(bytes20(_message.exocoreAddress));
            txn.expiryTime = block.timestamp + PROOF_TIMEOUT;
            txn.proofCount = 1;
            txn.witnessTime[msg.sender] = block.timestamp;
        }

        proofs[txTag].push(
            Proof({witness: msg.sender, message: _message, timestamp: block.timestamp, signature: _signature})
        );

        emit ProofSubmitted(txTag, msg.sender, _message);

        // Check for consensus
        if (txn.proofCount >= REQUIRED_PROOFS) {
            _processDeposit(txTag);
        }
    }

    /**
     * @notice Deposits BTC to the Exocore system.
     * @param _msg The interchain message containing the deposit details.
     * @param signature The signature to verify.
     */
    function depositTo(StakeMsg calldata _msg, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(_msg.amount)
        onlyAuthorizedWitness
    {
        require(authorizedWitnesses[msg.sender], "Not an authorized witness");
        (bytes memory txTag, address depositorExoAddr) = _processAndVerify(_msg, signature);

        processedBtcTxs[txTag] = TxInfo(true, block.timestamp);

        // we use registered exocore address as the depositor
        _deposit(getChainId(_msg.clientChain), _msg.srcAddress, depositorExoAddr, _msg.amount, _msg.txTag);
    }

    /**
     * @notice Delegates BTC to an operator.
     * @param token The value of the token enum.
     * @param operator The operator's exocore address.
     * @param amount The amount to delegate.
     */
    function delegateTo(Token token, string calldata operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(amount)
    {
        uint32 chainId = getChainIdByToken(token);
        uint64 nonce = ++delegationNonce[chainId][msg.sender];
        _delegate(chainId, nonce, msg.sender, operator, amount);
    }

    /**
     * @notice Undelegates BTC from an operator.
     * @param token The value of the token enum.
     * @param operator The operator's exocore address.
     * @param amount The amount to undelegate.
     */
    function undelegateFrom(Token token, string memory operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(amount)
    {
        uint32 chainId = getChainIdByToken(token);
        uint64 nonce = ++delegationNonce[chainId][msg.sender];
        bool success = DELEGATION_CONTRACT.undelegate(chainId, nonce, VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), bytes(operator), amount);
        if (!success) {
            revert UndelegationFailed();
        }
        emit UndelegationCompleted(chainId, msg.sender, operator, amount);
    }

    /**
     * @notice Withdraws the principal BTC.
     * @param token The value of the token enum.
     * @param amount The amount to withdraw.
     */
    function withdrawPrincipal(Token token, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(amount)
    {
        uint32 chainId = getChainIdByToken(token);
        (bool success, uint256 updatedBalance) =
            ASSETS_CONTRACT.withdrawLST(chainId, VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), amount);
        if (!success) {
            revert WithdrawPrincipalFailed();
        }

        (bytes32 requestId, bytes memory clientChainAddress) =
            _initiatePegOut(ClientChain(uint8(token)), amount, msg.sender, WithdrawType.WithdrawPrincipal);
        emit WithdrawPrincipalRequested(chainId, requestId, msg.sender, clientChainAddress, amount, updatedBalance);
    }

    /**
     * @notice Withdraws the reward BTC.
     * @param token The value of the token enum.
     * @param amount The amount to withdraw.
     */
    function withdrawReward(Token token, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(amount)
    {
        uint32 chainId = getChainIdByToken(token);
        (bool success, uint256 updatedBalance) =
            REWARD_CONTRACT.claimReward(chainId, VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), amount);
        if (!success) {
            revert WithdrawRewardFailed();
        }
        (bytes32 requestId, bytes memory clientChainAddress) =
            _initiatePegOut(ClientChain(uint8(token)), amount, msg.sender, WithdrawType.WithdrawReward);

        emit WithdrawRewardRequested(chainId, requestId, msg.sender, clientChainAddress, amount, updatedBalance);
    }

    /**
     * @notice Process a pending peg-out request
     * @dev Only authorized witnesses can call this function
     * @param _requestId The unique identifier of the peg-out request
     * @param _btcTxTag The Bitcoin transaction tag associated with the peg-out
     * @custom:throws InvalidRequestStatus if the request status is not Pending
     * @custom:throws RequestNotFound if the request does not exist
     */
    function processPegOut(bytes32 _requestId, bytes32 _btcTxTag)
        external
        onlyAuthorizedWitness
        nonReentrant
        whenNotPaused
    {
        PegOutRequest storage request = pegOutRequests[_requestId];

        // Check if the request exists and has the correct status
        if (request.requester == address(0)) {
            revert RequestNotFound(_requestId);
        }
        if (request.status != TxStatus.Pending) {
            revert InvalidRequestStatus(_requestId);
        }

        // Update request status
        request.status = TxStatus.Processed;

        // Emit event
        emit PegOutProcessed(_requestId, _btcTxTag);
    }

    // Function to check and update expired peg-out requests
    function checkExpiredPegOutRequests(bytes32[] calldata _requestIds) external {
        for (uint256 i = 0; i < _requestIds.length; i++) {
            PegOutRequest storage request = pegOutRequests[_requestIds[i]];
            if (request.status == TxStatus.Pending && block.timestamp >= request.timestamp + PROOF_TIMEOUT) {
                request.status = TxStatus.Expired;
                // Refund the tokens
                // require(token.mint(request.requester, request.amount), "Token minting failed");
                emit PegOutTransactionExpired(_requestIds[i]);
            }
        }
    }

    /**
     * @notice Deposits BTC and then delegates it to an operator.
     * @param _msg The interchain message containing the deposit details.
     * @param signature The signature to verify.
     */
    function depositThenDelegateTo(StakeMsg calldata _msg, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(_msg.amount)
        onlyAuthorizedWitness
    {
        (bytes memory txTag, address depositorExoAddr) = _processAndVerify(_msg, signature);
        uint32 srcChainId = getChainId(_msg.clientChain);
        _deposit(srcChainId, _msg.srcAddress, depositorExoAddr, _msg.amount, txTag);

        uint64 nonce = ++delegationNonce[srcChainId][msg.sender];
        _delegate(srcChainId, nonce, depositorExoAddr, _msg.operator, _msg.amount);
    }

    /**
     * @notice Gets the BTC address corresponding to an Exocore address.
     * @param exocoreAddress The Exocore address.
     * @return The corresponding BTC address.
     */
    function getBtcAddress(address exocoreAddress) external view returns (bytes memory) {
        return exocoreToBtcAddress[exocoreAddress];
    }

    /**
     * @notice Gets the current nonce for a given BTC address.
     * @param srcChainId The source chain ID.
     * @param depositor The BTC address as a string.
     * @return The current nonce.
     */
    function getCurrentNonce(uint32 srcChainId, string calldata depositor) external view returns (uint64) {
        bytes memory bytesBtcAddr = _stringToBytes(depositor);
        return inboundBytesNonce[srcChainId][bytesBtcAddr];
    }

    /**
     * @notice Sets the status of a PegOutRequest.
     * @param requestId The unique identifier of the request.
     * @param newStatus The new status to set.
     */
    function setPegOutRequestStatus(bytes32 requestId, TxStatus newStatus)
        external
        nonReentrant
        whenNotPaused
        onlyAuthorizedWitness
    {
        require(pegOutRequests[requestId].requester != address(0), "Request does not exist");
        pegOutRequests[requestId].status = newStatus;
        emit PegOutRequestStatusUpdated(requestId, newStatus);
    }

    /**
     * @notice Retrieves a PegOutRequest by its requestId.
     * @param requestId The unique identifier of the request.
     * @return The PegOutRequest struct associated with the given requestId.
     */
    function getPegOutRequest(bytes32 requestId) public view returns (PegOutRequest memory) {
        return pegOutRequests[requestId];
    }

    /**
     * @notice Converts a bytes32 to a string.
     * @param _bytes32 The bytes32 to convert.
     * @return string The resulting string.
     */
    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        bytes memory bytesArray = new bytes(32);
        assembly {
            mstore(add(bytesArray, 32), _bytes32)
        }
        return string(bytesArray);
    }

    /**
     * @notice Increments and gets the next nonce for a given source address.
     * @param srcChainId The source chain ID.
     * @param exocoreAddress The exocore address.
     * @return The next nonce for corresponding btcAddress.
     */
    function _nextNonce(uint32 srcChainId, address exocoreAddress) internal view returns (uint64) {
        bytes memory depositor = exocoreToBtcAddress[exocoreAddress];
        return inboundBytesNonce[srcChainId][depositor] + 1;
    }

    /**
     * @notice Checks if a witness is authorized.
     * @param witness The witness address.
     * @return True if the witness is authorized, false otherwise.
     */
    function _isAuthorizedWitness(address witness) internal view returns (bool) {
        // Implementation depends on how you determine if a witness is authorized
        // For example, you might check against a list of authorized witnesss
        // or query another contract
        return authorizedWitnesses[witness];
    }

    /**
     * @notice Converts a string to bytes.
     * @param source The string to convert.
     * @return The string as bytes.
     */
    function _stringToBytes(string memory source) internal pure returns (bytes memory) {
        return abi.encodePacked(source);
    }

    /**
     * @notice Registers or updates the Bitcoin chain with the Exocore system.
     */
    function _registerOrUpdateClientChain(uint32 chainId, uint8 stakerAccountLength, string memory name, string memory metadata, string memory signatureScheme) internal {
        (bool success, bool updated) = ASSETS_CONTRACT.registerOrUpdateClientChain(
            chainId, stakerAccountLength, name, metadata, signatureScheme
        );
        if (!success) {
            revert Errors.RegisterClientChainToExocoreFailed(chainId);
        }
        if (updated) {
            emit ClientChainUpdated(chainId);
        } else {
            emit ClientChainRegistered(chainId);
        }
    }

    function _registerOrUpdateToken(uint32 chainId, bytes memory token, uint8 decimals, string memory name, string memory metadata, string memory oracleInfo) internal {
        bool registered = ASSETS_CONTRACT.registerToken(chainId, token, decimals, name, metadata, oracleInfo);
        if (!registered) {
            bool updated = ASSETS_CONTRACT.updateToken(chainId, token, metadata);
            if (!updated) {
                revert Errors.AddWhitelistTokenFailed(chainId, bytes32(token));
            }
            emit WhitelistTokenUpdated(chainId, VIRTUAL_TOKEN_ADDRESS);
        } else {
            emit WhitelistTokenAdded(chainId, VIRTUAL_TOKEN_ADDRESS);
        }
    }

    /**
     * @notice Checks if the proofs for a transaction are consistent.
     * @param _txTag The transaction tag to check.
     * @return bool True if proofs are consistent, false otherwise.
     */
    function _areProofsConsistent(bytes memory _txTag) internal view returns (bool) {
        Proof[] storage txProofs = proofs[_txTag];
        if (txProofs.length < REQUIRED_PROOFS) {
            return false;
        }

        StakeMsg memory firstMsg = txProofs[0].message;
        for (uint256 i = 1; i < txProofs.length; i++) {
            StakeMsg memory currentMsg = txProofs[i].message;
            if (
                firstMsg.clientChain != currentMsg.clientChain
                    || firstMsg.exocoreAddress != currentMsg.exocoreAddress
                    || keccak256(bytes(firstMsg.operator)) != keccak256(bytes(currentMsg.operator))
                    || firstMsg.amount != currentMsg.amount
                    || firstMsg.nonce != currentMsg.nonce || keccak256(firstMsg.txTag) != keccak256(currentMsg.txTag)
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice Verifies the signature of an interchain message.
     * @param _msg The interchain message.
     * @param signature The signature to verify.
     */
    function _verifySignature(StakeMsg calldata _msg, bytes memory signature) internal view {
        // StakeMsg, EIP721 is preferred next step.
        bytes memory encodeMsg = abi.encode(
            _msg.clientChain,
            _msg.srcAddress,
            _msg.operator,
            _msg.amount,
            _msg.nonce,
            _msg.txTag
        );
        bytes32 messageHash = keccak256(encodeMsg);

        SignatureVerifier.verifyMsgSig(msg.sender, messageHash, signature);
    }

    /**
     * @notice Processes and verifies an interchain message.
     * @param _msg The interchain message.
     * @param signature The signature to verify.
     * @return txTag The lowercase of BTC txid-vout.
     * @return depositorExoAddress The Exocore address of the depositor.
     */
    function _processAndVerify(StakeMsg calldata _msg, bytes calldata signature)
        internal
        returns (bytes memory txTag, address depositorExoAddress)
    {
        txTag = _msg.txTag;
        depositorExoAddress = btcToExocoreAddress[_msg.srcAddress];
        if (depositorExoAddress == address(0)) {
            revert BtcAddressNotRegistered();
        }

        if (processedBtcTxs[txTag].processed) {
            revert BtcTxAlreadyProcessed();
        }

        // Verify nonce
        _verifyAndUpdateBytesNonce(getChainId(_msg.clientChain), _msg.srcAddress, _msg.nonce);

        // Verify signature
        _verifySignature(_msg, signature);
    }

    /**
     * @notice Processes a deposit after sufficient proofs have been submitted.
     * @param _txTag The transaction tag of the deposit to process.
     */
    function _processDeposit(bytes memory _txTag) internal {
        Transaction storage txn = transactions[_txTag];
        require(txn.status == TxStatus.Pending, "Transaction not pending");
        require(txn.proofCount >= REQUIRED_PROOFS, "Insufficient proofs");

        // Verify proof consistency
        require(_areProofsConsistent(_txTag), "Inconsistent proofs");

        // Calculate fee
        uint256 fee = (txn.amount * bridgeFee) / 10_000;
        uint256 amountAfterFee = txn.amount - fee;

        //todo:call precompile depositTo
        _deposit(getChainId(txn.clientChain), txn.srcAddress, txn.recipient, txn.amount, _txTag);
        txn.status = TxStatus.Processed;

        // totalDeposited += txn.amount;

        emit DepositProcessed(_txTag, txn.recipient, amountAfterFee);
    }

    /**
     * @notice Initiates a peg-out request for a given token amount to a Bitcoin address
     * @dev This function creates a new peg-out request and stores it in the contract's state
     * @param clientChain The client chain to be pegged out
     * @param _amount The amount of tokens to be pegged out
     * @param withdrawer The Exocore address associated with the Bitcoin address
     * @param _withdrawType The type of withdrawal (e.g., normal, fast)
     * @return requestId The unique identifier for the peg-out request
     * @return clientChainAddress The client chain address for the peg-out
     * @custom:throws BtcAddressNotRegistered if the Bitcoin address is not registered for the given Exocore address
     * @custom:throws RequestAlreadyExists if a request with the same parameters already exists
     */
    function _initiatePegOut(ClientChain clientChain, uint256 _amount, address withdrawer, WithdrawType _withdrawType)
        internal
        returns (bytes32 requestId, bytes memory clientChainAddress)
    {
        // Use storage pointer to reduce gas consumption
        PegOutRequest storage request;

        // 1. Check client c address
        clientChainAddress = exocoreToBtcAddress[withdrawer];
        if (clientChainAddress.length == 0) {
            revert BtcAddressNotRegistered();
        }

        // 2. Generate unique requestId
        requestId = keccak256(abi.encodePacked(clientChain, withdrawer, clientChainAddress, _amount, block.number));

        // 3. Check if request already exists
        request = pegOutRequests[requestId];
        if (request.requester != address(0)) {
            revert RequestAlreadyExists(requestId);
        }

        // 4. Create new PegOutRequest
        request.clientChain = clientChain;
        request.requester = withdrawer;
        request.clientChainAddress = clientChainAddress;
        request.amount = _amount;
        request.withdrawType = _withdrawType;
        request.status = TxStatus.Pending;
        request.timestamp = block.timestamp;
    }

    /**
     * @notice Internal function to deposit BTC like token.
     * @param clientChainId The client chain ID.
     * @param srcAddress The source address.
     * @param depositorExoAddr The Exocore address.
     * @param amount The amount to deposit.
     * @param txTag The transaction tag.
     */
    function _deposit(
        uint32 clientChainId,
        bytes memory srcAddress,
        address depositorExoAddr,
        uint256 amount,
        bytes memory txTag
    ) internal {
        (bool success, uint256 updatedBalance) =
            ASSETS_CONTRACT.depositLST(clientChainId, VIRTUAL_TOKEN, depositorExoAddr.toExocoreBytes(), amount);
        if (!success) {
            revert DepositFailed(txTag);
        }

        emit DepositCompleted(clientChainId, txTag, depositorExoAddr, srcAddress, amount, updatedBalance);
    }

    /**
     * @notice Internal function to delegate BTC like token.
     * @param clientChainId The client chain ID.
     * @param delegator The Exocore address.
     * @param operator The operator's address.
     * @param amount The amount to delegate.
     */
    function _delegate(
        uint32 clientChainId,
        uint64 nonce,
        address delegator,
        string memory operator,
        uint256 amount
    ) internal {
        bool success = DELEGATION_CONTRACT.delegate(clientChainId, nonce, VIRTUAL_TOKEN, delegator.toExocoreBytes(), bytes(operator), amount);
        if (!success) {
            revert DelegationFailed();
        }
        emit DelegationCompleted(clientChainId, delegator, operator, amount);
    }

    function _revokeTxIfExpired(bytes calldata txTag) internal {
        Transaction storage txn = transactions[txTag];
        if (txn.status == TxStatus.Pending && block.timestamp >= txn.expiryTime) {
            txn.status = TxStatus.Expired;
            emit TransactionExpired(txTag);
        }
    }

    // encode address as byte array with 32 bytes, and pad with zeros from right
    function addressToExocoreBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }

}
