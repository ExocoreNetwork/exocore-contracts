// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

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

    uint32 internal CLIENT_CHAIN_ID;
    address internal constant BTC_ADDR = address(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    bytes internal constant BTC_TOKEN = abi.encodePacked(bytes32(bytes20(BTC_ADDR)));

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
        // todo: for test.
        _registerClientChain(111);
        authorizedWitnesses[EXOCORE_WITNESS] = true;
        isWhitelistedToken[BTC_ADDR] = true;
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
    function removeWitness(address _witness) public onlyOwner {
        require(authorizedWitnesses[_witness], "Witness not authorized");
        authorizedWitnesses[_witness] = false;
        emit WitnessRemoved(_witness);
    }

    /**
     * @notice Updates the bridge fee.
     * @param _newFee The new fee to be set (in basis points, max 1000 or 10%).
     * @dev Can only be called by the contract owner.
     */
    function updateBridgeFee(uint256 _newFee) public onlyOwner {
        require(_newFee <= 1000, "Fee cannot exceed 10%"); // Max fee of 10%
        bridgeFee = _newFee;
        emit BridgeFeeUpdated(_newFee);
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

        InterchainMsg memory firstMsg = txProofs[0].message;
        for (uint256 i = 1; i < txProofs.length; i++) {
            InterchainMsg memory currentMsg = txProofs[i].message;
            if (
                firstMsg.srcChainID != currentMsg.srcChainID || 
                firstMsg.dstChainID != currentMsg.dstChainID ||
                keccak256(firstMsg.srcAddress) != keccak256(currentMsg.srcAddress) ||
                keccak256(firstMsg.dstAddress) != keccak256(currentMsg.dstAddress) ||
                firstMsg.token != currentMsg.token || 
                firstMsg.amount != currentMsg.amount ||
                firstMsg.nonce != currentMsg.nonce || 
                keccak256(firstMsg.txTag) != keccak256(currentMsg.txTag) ||
                keccak256(firstMsg.payload) != keccak256(currentMsg.payload)
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice Checks and updates expired transactions.
     * @param _txTags An array of transaction tags to check.
     */
    function checkExpiredTransactions(bytes[] calldata _txTags) public {
        for (uint256 i = 0; i < _txTags.length; i++) {
            Transaction storage txn = transactions[_txTags[i]];
            if (txn.status == TxStatus.Pending && block.timestamp >= txn.expiryTime) {
                txn.status = TxStatus.Expired;
                emit TransactionExpired(_txTags[i]);
            }
        }
    }

    /**
     * @notice Registers the client chain ID with the Exocore system.
     * @param clientChainId The ID of the client chain.
     * @dev This function should be implemented in ExocoreGateway.
     */
    function _registerClientChain(uint32 clientChainId) internal {
        if (clientChainId == 0) {
            revert ZeroAddressNotAllowed();
        }
        // if (!ASSETS_CONTRACT.registerClientChain(clientChainId)) {
        //     revert RegisterClientChainToExocoreFailed(clientChainId);
        // }
        CLIENT_CHAIN_ID = clientChainId;
    }

    /**
     * @notice Registers a BTC address with an Exocore address.
     * @param depositor The BTC address to register.
     * @param exocoreAddress The corresponding Exocore address.
     * @dev Can only be called by an authorized witness.
     */
    function registerAddress(bytes calldata depositor, bytes calldata exocoreAddress) external onlyAuthorizedWitness {
        require(depositor.length > 0 && exocoreAddress.length > 0, "Invalid address");
        require(btcToExocoreAddress[depositor].length == 0, "Depositor address already registered");
        require(exocoreToBtcAddress[exocoreAddress].length == 0, "Exocore address already registered");

        btcToExocoreAddress[depositor] = exocoreAddress;
        exocoreToBtcAddress[exocoreAddress] = depositor;

        emit AddressRegistered(depositor, exocoreAddress);
    }

    /**
     * @notice Verifies the signature of an interchain message.
     * @param _msg The interchain message.
     * @param signature The signature to verify.
     */
    function _verifySignature(InterchainMsg calldata _msg, bytes memory signature) internal view {
        // InterchainMsg, EIP721 is preferred next step.
        bytes memory encodeMsg = abi.encode(
            _msg.srcChainID,
            _msg.dstChainID,
            _msg.srcAddress,
            _msg.dstAddress,
            _msg.token,
            _msg.amount,
            _msg.nonce,
            _msg.txTag,
            _msg.payload
        );
        bytes32 messageHash = keccak256(encodeMsg);

        SignatureVerifier.verifyMsgSig(msg.sender, messageHash, signature);
    }

    /**
     * @notice Converts a bytes32 to a string.
     * @param _bytes32 The bytes32 to convert.
     * @return string The resulting string.
     */
    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        bytes memory bytesArray = new bytes(32);
        for (uint256 i; i < 32; i++) {
            bytesArray[i] = _bytes32[i];
        }
        return string(bytesArray);
    }
    /**
     * @notice Processes and verifies an interchain message.
     * @param _msg The interchain message.
     * @param signature The signature to verify.
     * @return btcTxTag The lowercase of BTC txid-vout.
     * @return depositor The BTC address.
     */

    function _processAndVerify(InterchainMsg calldata _msg, bytes calldata signature)
        internal
        returns (bytes memory btcTxTag, bytes memory depositor)
    {
        btcTxTag = _msg.txTag;
        depositor = btcToExocoreAddress[_msg.srcAddress];
        if (depositor.length == 0) {
            revert BtcAddressNotRegistered();
        }

        if (processedBtcTxs[btcTxTag].processed) {
            revert BtcTxAlreadyProcessed();
        }

        // Verify nonce
        _verifyAndUpdateBytesNonce(_msg.srcChainID, depositor, _msg.nonce);

        // Verify signature
        _verifySignature(_msg, signature);
    }

    /**
     * @notice Submits a proof for a transaction.
     * @param _message The interchain message.
     * @param _signature The signature of the message.
     */
    function submitProof(InterchainMsg calldata _message, bytes calldata _signature)
        public
        nonReentrant
        whenNotPaused
    {
        // Verify the signature
        if (processedBtcTxs[_message.txTag].processed) {
            revert BtcTxAlreadyProcessed();
        }

        // Verify nonce
        _verifyAndUpdateBytesNonce(_message.srcChainID, _message.srcAddress, _message.nonce);

        // Verify signature
        _verifySignature(_message, _signature);

        bytes memory txTag = _message.txTag;
        Transaction storage txn = transactions[txTag];

        if (txn.status == TxStatus.Pending) {
            require(!txn.hasWitnessed[msg.sender], "Witness has already submitted proof");
            txn.hasWitnessed[msg.sender] = true;
            txn.proofCount++;
        } else {
            txn.status = TxStatus.Pending;
            txn.amount = _message.amount;
            txn.recipient = address(bytes20(_message.dstAddress));
            txn.expiryTime = block.timestamp + PROOF_TIMEOUT;
            txn.proofCount = 1;
            txn.hasWitnessed[msg.sender] = true;
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

        txn.status = TxStatus.Processed;

        // totalDeposited += txn.amount;

        emit DepositProcessed(_txTag, txn.recipient, amountAfterFee);
    }

    /**
     * @notice Deposits BTC to the Exocore system.
     * @param _msg The interchain message containing the deposit details.
     * @param signature The signature to verify.
     */
    function depositTo(InterchainMsg calldata _msg, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(_msg.token)
        isValidAmount(_msg.amount)
        onlyAuthorizedWitness
    {
        require(authorizedWitnesses[msg.sender], "Not an authorized witness");
        (bytes memory btcTxTag, bytes memory depositorExoAddr) = _processAndVerify(_msg, signature);

        processedBtcTxs[btcTxTag] = TxInfo(true, block.timestamp);

        //TODO: this depositor can be exocore address or btc address.
        (bool success, uint256 updatedBalance) =
            ASSETS_CONTRACT.depositLST(_msg.srcChainID, BTC_TOKEN, depositorExoAddr, _msg.amount);
        if (!success) {
            revert DepositFailed(btcTxTag);
        }
        // console.log("depositTo success");
        emit DepositCompleted(btcTxTag, depositorExoAddr, BTC_ADDR, _msg.srcAddress, _msg.amount, updatedBalance);
    }

    /**
     * @notice Delegates BTC to an operator.
     * @param token The token address.
     * @param operator The operator's exocore address.
     * @param amount The amount to delegate.
     */
    function delegateTo(address token, bytes calldata operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        bytes memory delegator = abi.encodePacked(bytes32(bytes20(msg.sender)));
        _nextNonce(CLIENT_CHAIN_ID, delegator);
        try DELEGATION_CONTRACT.delegateToThroughBtcGateway(CLIENT_CHAIN_ID, BTC_TOKEN, delegator, operator, amount)
        returns (bool success) {
            if (!success) {
                revert DelegationFailed();
            }
            emit DelegationCompleted(token, delegator, operator, amount);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert DelegationFailed();
        }
    }

    /**
     * @notice Undelegates BTC from an operator.
     * @param token The token address.
     * @param operator The operator's exocore address.
     * @param amount The amount to undelegate.
     */
    function undelegateFrom(address token, bytes calldata operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        bytes memory delegator = abi.encodePacked(bytes32(bytes20(msg.sender)));
        _nextNonce(CLIENT_CHAIN_ID, delegator);
        try DELEGATION_CONTRACT.undelegateFromThroughBtcGateway(CLIENT_CHAIN_ID, BTC_TOKEN, delegator, operator, amount)
        returns (bool success) {
            if (!success) {
                revert UndelegationFailed();
            }
            emit UndelegationCompleted(token, delegator, operator, amount);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert UndelegationFailed();
        }
    }

    /**
     * @notice Withdraws the principal BTC.
     * @param token The token address.
     * @param amount The amount to withdraw.
     */
    function withdrawPrincipal(address token, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        bytes memory withdrawer = abi.encodePacked(bytes32(bytes20(msg.sender)));
        _nextNonce(CLIENT_CHAIN_ID, withdrawer);
        (bool success, uint256 updatedBalance) =
            ASSETS_CONTRACT.withdrawLST(CLIENT_CHAIN_ID, BTC_TOKEN, withdrawer, amount);
        if (!success) {
            revert WithdrawPrincipalFailed();
        }
        (bytes32 requestId, bytes memory _btcAddress) =
            _initiatePegOut(token, amount, withdrawer, WithdrawType.WithdrawPrincipal);
        emit WithdrawPrincipalRequested(requestId, msg.sender, token, _btcAddress, amount, updatedBalance);
    }

    /**
     * @notice Withdraws the reward BTC.
     * @param token The token address.
     * @param amount The amount to withdraw.
     */
    function withdrawReward(address token, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        bytes memory withdrawer = abi.encodePacked(bytes32(bytes20(msg.sender)));
        _nextNonce(CLIENT_CHAIN_ID, withdrawer);
        (bool success, uint256 updatedBalance) =
            REWARD_CONTRACT.claimReward(CLIENT_CHAIN_ID, BTC_TOKEN, withdrawer, amount);
        if (!success) {
            revert WithdrawRewardFailed();
        }
        (bytes32 requestId, bytes memory _btcAddress) =
            _initiatePegOut(token, amount, withdrawer, WithdrawType.WithdrawReward);

        emit WithdrawRewardRequested(requestId, msg.sender, token, _btcAddress, amount, updatedBalance);
    }

    /**
     * @notice Initiates a peg-out request for a given token amount to a Bitcoin address
     * @dev This function creates a new peg-out request and stores it in the contract's state
     * @param _token The address of the token to be pegged out
     * @param _amount The amount of tokens to be pegged out
     * @param withdrawer The Exocore address associated with the Bitcoin address
     * @param _withdrawType The type of withdrawal (e.g., normal, fast)
     * @return requestId The unique identifier for the peg-out request
     * @return _btcAddress The Bitcoin address for the peg-out
     * @custom:throws BtcAddressNotRegistered if the Bitcoin address is not registered for the given Exocore address
     * @custom:throws RequestAlreadyExists if a request with the same parameters already exists
     */
    function _initiatePegOut(address _token, uint256 _amount, bytes memory withdrawer, WithdrawType _withdrawType)
        internal
        returns (bytes32 requestId, bytes memory _btcAddress)
    {
        // Use storage pointer to reduce gas consumption
        PegOutRequest storage request;

        // 1. Check BTC address
        _btcAddress = exocoreToBtcAddress[withdrawer];
        if (_btcAddress.length == 0) {
            revert BtcAddressNotRegistered();
        }

        // 2. Generate unique requestId
        requestId = keccak256(abi.encodePacked(_token, msg.sender, _btcAddress, _amount, block.number));

        // 3. Check if request already exists
        request = pegOutRequests[requestId];
        if (request.requester != address(0)) {
            revert RequestAlreadyExists(requestId);
        }

        // 4. Create new PegOutRequest
        request.token = _token;
        request.requester = msg.sender;
        request.btcAddress = _btcAddress;
        request.amount = _amount;
        request.withdrawType = _withdrawType;
        request.status = TxStatus.Pending;
        request.timestamp = block.timestamp;
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
        public
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
    function checkExpiredPegOutRequests(bytes32[] calldata _requestIds) public {
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
     * @param operator The operator's address.
     * @param signature The signature to verify.
     */
    function depositThenDelegateTo(InterchainMsg calldata _msg, bytes calldata operator, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(BTC_ADDR)
        isValidAmount(_msg.amount)
        onlyAuthorizedWitness
    {
        (bytes memory btcTxTag, bytes memory depositor) = _processAndVerify(_msg, signature);
        _depositToAssetContract(CLIENT_CHAIN_ID, BTC_TOKEN, depositor, _msg.amount, btcTxTag, operator);
    }

    /**
     * @notice Internal function to deposit BTC to the asset contract.
     * @param clientChainId The client chain ID.
     * @param btcToken The BTC token.
     * @param depositor The BTC address.
     * @param amount The amount to deposit.
     * @param btcTxTag The BTC transaction tag.
     * @param operator The operator's address.
     */
    function _depositToAssetContract(
        uint32 clientChainId,
        bytes memory btcToken,
        bytes memory depositor,
        uint256 amount,
        bytes memory btcTxTag,
        bytes memory operator
    ) internal {
        try ASSETS_CONTRACT.depositLST(clientChainId, btcToken, depositor, amount) returns (
            bool depositSuccess, uint256 updatedBalance
        ) {
            if (!depositSuccess) {
                revert DepositFailed(btcTxTag);
            }
            processedBtcTxs[btcTxTag] = TxInfo(true, block.timestamp);
            _delegateToDelegationContract(clientChainId, btcToken, depositor, operator, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert DepositFailed(btcTxTag);
        }
    }

    /**
     * @notice Internal function to delegate BTC to the delegation contract.
     * @param clientChainId The client chain ID.
     * @param btcToken The BTC token.
     * @param depositor The BTC address.
     * @param operator The operator's address.
     * @param amount The amount to delegate.
     * @param updatedBalance The updated balance after delegation.
     */
    function _delegateToDelegationContract(
        uint32 clientChainId,
        bytes memory btcToken,
        bytes memory depositor,
        bytes memory operator,
        uint256 amount,
        uint256 updatedBalance
    ) internal {
        try DELEGATION_CONTRACT.delegateToThroughBtcGateway(clientChainId, btcToken, depositor, operator, amount)
        returns (bool delegateSuccess) {
            if (!delegateSuccess) {
                revert DelegationFailed();
            }
            emit DepositAndDelegationCompleted(BTC_ADDR, depositor, operator, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert DelegationFailed();
        }
    }

    /**
     * @notice Gets the BTC address corresponding to an Exocore address.
     * @param exocoreAddress The Exocore address.
     * @return The corresponding BTC address.
     */
    function getBtcAddress(bytes calldata exocoreAddress) external view returns (bytes memory) {
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
     * @notice Retrieves a PegOutRequest by its requestId.
     * @param requestId The unique identifier of the request.
     * @return The PegOutRequest struct associated with the given requestId.
     */
    function getPegOutRequest(bytes32 requestId) public view returns (PegOutRequest memory) {
        return pegOutRequests[requestId];
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
     * @notice Converts an address to bytes.
     * @param addr The address to convert.
     * @return The address as bytes.
     */
    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(addr);
    }

    /**
     * @notice Increments and gets the next nonce for a given source address.
     * @param srcChainId The source chain ID.
     * @param exoSrcAddress The exocore source address.
     * @return The next nonce for corresponding btcAddress.
     */
    function _nextNonce(uint32 srcChainId, bytes memory exoSrcAddress) internal view returns (uint64) {
        bytes memory depositor = exocoreToBtcAddress[exoSrcAddress];
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

}
