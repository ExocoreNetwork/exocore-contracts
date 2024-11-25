// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Errors} from "../libraries/Errors.sol";
import {ExocoreBytes} from "../libraries/ExocoreBytes.sol";

import {ASSETS_CONTRACT} from "../interfaces/precompiles/IAssets.sol";
import {DELEGATION_CONTRACT} from "../interfaces/precompiles/IDelegation.sol";
import {REWARD_CONTRACT} from "../interfaces/precompiles/IReward.sol";
import {SignatureVerifier} from "../libraries/SignatureVerifier.sol";
import {UTXOGatewayStorage} from "../storage/UTXOGatewayStorage.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/**
 * @title UTXOGateway
 * @dev This contract manages the gateway between Bitcoin like chains and the Exocore system.
 * It handles deposits, delegations, withdrawals, and peg-out requests for BTC like tokens.
 */
contract UTXOGateway is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    UTXOGatewayStorage
{

    using ExocoreBytes for address;
    using SignatureVerifier for bytes32;

    /**
     * @notice Constructor to initialize the contract with the client chain ID.
     * @dev Sets up initial configuration for testing purposes.
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with the Exocore witness address, owner address and required proofs.
     * @dev If the witnesses length is greater or equal to the required proofs, the consensus requirement for stake
     * message
     * would be activated.
     * @param owner_ The address of the owner.
     * @param witnesses The addresses of the witnesses.
     * @param requiredProofs_ The number of required proofs.
     */
    function initialize(address owner_, address[] calldata witnesses, uint256 requiredProofs_) external initializer {
        if (owner_ == address(0) || witnesses.length == 0) {
            revert Errors.ZeroAddress();
        }
        if (requiredProofs_ < MIN_REQUIRED_PROOFS || requiredProofs_ > MAX_REQUIRED_PROOFS) {
            revert Errors.InvalidRequiredProofs();
        }

        requiredProofs = requiredProofs_;
        for (uint256 i = 0; i < witnesses.length; i++) {
            _addWitness(witnesses[i]);
        }
        __Pausable_init_unchained();
        __ReentrancyGuard_init_unchained();
        _transferOwnership(owner_);
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
     * @notice Activates token staking by registering or updating the chain and token with the Exocore system.
     */
    function activateStakingForClientChain(ClientChainID clientChain_) external onlyOwner whenNotPaused {
        if (clientChain_ == ClientChainID.Bitcoin) {
            _registerOrUpdateClientChain(
                clientChain_, STAKER_ACCOUNT_LENGTH, BITCOIN_NAME, BITCOIN_METADATA, BITCOIN_SIGNATURE_SCHEME
            );
            _registerOrUpdateToken(clientChain_, VIRTUAL_TOKEN, BTC_DECIMALS, BTC_NAME, BTC_METADATA, BTC_ORACLE_INFO);
        } else {
            revert Errors.InvalidClientChain();
        }
    }

    /**
     * @notice Updates the required proofs for consensus.
     * @notice The consensus requirement for stake message would be activated if the current authorized witness count is
     * greater than or equal to the new required proofs.
     * @dev Can only be called by the contract owner.
     * @param newRequiredProofs The new required proofs.
     */
    function updateRequiredProofs(uint256 newRequiredProofs) external onlyOwner whenNotPaused {
        if (newRequiredProofs < MIN_REQUIRED_PROOFS || newRequiredProofs > MAX_REQUIRED_PROOFS) {
            revert Errors.InvalidRequiredProofs();
        }

        bool wasConsensusRequired = _isConsensusRequired();
        uint256 oldRequiredProofs = requiredProofs;
        requiredProofs = newRequiredProofs;

        emit RequiredProofsUpdated(oldRequiredProofs, newRequiredProofs);

        // Check if consensus state changed due to new requirement
        bool isConsensusRequired_ = _isConsensusRequired();
        if (!wasConsensusRequired && isConsensusRequired_) {
            emit ConsensusActivated(requiredProofs, authorizedWitnessCount);
        } else if (wasConsensusRequired && !isConsensusRequired_) {
            emit ConsensusDeactivated(requiredProofs, authorizedWitnessCount);
        }
    }

    /**
     * @notice Adds a new authorized witness.
     * @param _witness The address of the witness to be added.
     * @dev Can only be called by the contract owner.
     */
    function addWitness(address _witness) external onlyOwner whenNotPaused {
        _addWitness(_witness);
    }

    /**
     * @notice Removes an authorized witness.
     * @param _witness The address of the witness to be removed.
     * @dev Can only be called by the contract owner.
     * @custom:throws CannotRemoveLastWitness if the last witness is being removed
     */
    function removeWitness(address _witness) external onlyOwner whenNotPaused {
        if (authorizedWitnessCount <= 1) {
            revert Errors.CannotRemoveLastWitness();
        }
        if (!authorizedWitnesses[_witness]) {
            revert Errors.WitnessNotAuthorized(_witness);
        }

        bool wasConsensusRequired = _isConsensusRequired();

        authorizedWitnesses[_witness] = false;
        authorizedWitnessCount--;
        emit WitnessRemoved(_witness);

        // Emit only when crossing the threshold from true to false
        if (wasConsensusRequired && !_isConsensusRequired()) {
            emit ConsensusDeactivated(requiredProofs, authorizedWitnessCount);
        }
    }

    /**
     * @notice Updates the bridge fee rate.
     * @param bridgeFeeRate_ The new bridge fee rate, with basis as 10000, so 100 means 1%
     * @dev Can only be called by the contract owner.
     */
    function updateBridgeFeeRate(uint256 bridgeFeeRate_) external onlyOwner whenNotPaused {
        require(bridgeFeeRate_ <= MAX_BRIDGE_FEE_RATE, "Fee cannot exceed max bridge fee rate");
        bridgeFeeRate = bridgeFeeRate_;
        emit BridgeFeeRateUpdated(bridgeFeeRate_);
    }

    /**
     * @notice Submits a proof for a stake message.
     * @notice The submitted message would be processed after collecting enough proofs from withnesses.
     * @dev The stake message would be deleted after it has been processed to refund some gas, though the mapping
     * inside it cannot be deleted.
     * @param witness The witness address that signed the message.
     * @param _message The stake message.
     * @param _signature The signature of the message.
     */
    // slither-disable-next-line reentrancy-no-eth
    function submitProofForStakeMsg(address witness, StakeMsg calldata _message, bytes calldata _signature)
        external
        nonReentrant
        whenNotPaused
    {
        if (!_isConsensusRequired()) {
            revert Errors.ConsensusNotRequired();
        }

        if (!_isAuthorizedWitness(witness)) {
            revert Errors.WitnessNotAuthorized(witness);
        }

        bytes32 messageHash = _verifyStakeMessage(witness, _message, _signature);

        // we should revoke the tx by setting it as expired if it has expired
        _revokeTxIfExpired(messageHash);

        Transaction storage txn = transactions[messageHash];

        if (txn.status == TxStatus.Pending) {
            // if the witness has already submitted proof at or after the start of the proof window, they cannot submit
            // again
            if (txn.witnessTime[witness] >= txn.expiryTime - PROOF_TIMEOUT) {
                revert Errors.WitnessAlreadySubmittedProof();
            }
            txn.witnessTime[witness] = block.timestamp;
            txn.proofCount++;
        } else {
            txn.status = TxStatus.Pending;
            txn.expiryTime = block.timestamp + PROOF_TIMEOUT;
            txn.proofCount = 1;
            txn.witnessTime[witness] = block.timestamp;
            txn.stakeMsg = _message;
        }

        emit ProofSubmitted(messageHash, witness);

        // Check for consensus
        if (txn.proofCount >= requiredProofs) {
            processedTransactions[messageHash] = true;
            _processStakeMsg(txn.stakeMsg);
            // we delete the transaction after it has been processed to refund some gas, so no need to worry about
            // reentrancy
            delete transactions[messageHash];

            emit TransactionProcessed(messageHash);
        }
    }

    /**
     * @notice Deposits BTC like tokens to the Exocore system.
     * @param witness The witness address that signed the message.
     * @param _msg The stake message.
     * @param signature The signature of the message.
     */
    function processStakeMessage(address witness, StakeMsg calldata _msg, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
    {
        if (_isConsensusRequired()) {
            revert Errors.ConsensusRequired();
        }

        if (!_isAuthorizedWitness(witness)) {
            revert Errors.WitnessNotAuthorized(witness);
        }
        _verifyStakeMessage(witness, _msg, signature);

        _processStakeMsg(_msg);
    }

    /**
     * @notice Delegates BTC like tokens to an operator.
     * @param token The value of the token enum.
     * @param operator The operator's exocore address.
     * @param amount The amount to delegate.
     */
    function delegateTo(Token token, string calldata operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(amount)
        isRegistered(token, msg.sender)
    {
        if (!isValidOperatorAddress(operator)) {
            revert Errors.InvalidOperator();
        }

        ClientChainID chainId = ClientChainID(uint8(token));

        bool success = _delegate(chainId, msg.sender, operator, amount);
        if (!success) {
            revert Errors.DelegationFailed();
        }

        emit DelegationCompleted(chainId, msg.sender, operator, amount);
    }

    /**
     * @notice Undelegates BTC like tokens from an operator.
     * @param token The value of the token enum.
     * @param operator The operator's exocore address.
     * @param amount The amount to undelegate.
     */
    function undelegateFrom(Token token, string calldata operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(amount)
        isRegistered(token, msg.sender)
    {
        if (!isValidOperatorAddress(operator)) {
            revert Errors.InvalidOperator();
        }

        ClientChainID chainId = ClientChainID(uint8(token));

        uint64 nonce = ++delegationNonce[chainId];
        bool success = DELEGATION_CONTRACT.undelegate(
            uint32(uint8(chainId)), nonce, VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), bytes(operator), amount
        );
        if (!success) {
            revert Errors.UndelegationFailed();
        }
        emit UndelegationCompleted(chainId, msg.sender, operator, amount);
    }

    /**
     * @notice Withdraws the principal BTC like tokens.
     * @param token The value of the token enum.
     * @param amount The amount to withdraw.
     */
    function withdrawPrincipal(Token token, uint256 amount) external nonReentrant whenNotPaused isValidAmount(amount) {
        ClientChainID chainId = ClientChainID(uint8(token));

        bytes memory clientChainAddress = outboundRegistry[chainId][msg.sender];
        if (clientChainAddress.length == 0) {
            revert Errors.AddressNotRegistered();
        }

        (bool success, uint256 updatedBalance) =
            ASSETS_CONTRACT.withdrawLST(uint32(uint8(chainId)), VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), amount);
        if (!success) {
            revert Errors.WithdrawPrincipalFailed();
        }

        uint64 requestId =
            _initiatePegOut(chainId, amount, msg.sender, clientChainAddress, WithdrawType.WithdrawPrincipal);
        emit WithdrawPrincipalRequested(chainId, requestId, msg.sender, clientChainAddress, amount, updatedBalance);
    }

    /**
     * @notice Withdraws the reward BTC like tokens.
     * @param token The value of the token enum.
     * @param amount The amount to withdraw.
     */
    function withdrawReward(Token token, uint256 amount) external nonReentrant whenNotPaused isValidAmount(amount) {
        ClientChainID chainId = ClientChainID(uint8(token));
        bytes memory clientChainAddress = outboundRegistry[chainId][msg.sender];
        if (clientChainAddress.length == 0) {
            revert Errors.AddressNotRegistered();
        }

        (bool success, uint256 updatedBalance) =
            REWARD_CONTRACT.claimReward(uint32(uint8(chainId)), VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), amount);
        if (!success) {
            revert Errors.WithdrawRewardFailed();
        }

        uint64 requestId = _initiatePegOut(chainId, amount, msg.sender, clientChainAddress, WithdrawType.WithdrawReward);
        emit WithdrawRewardRequested(chainId, requestId, msg.sender, clientChainAddress, amount, updatedBalance);
    }

    /**
     * @notice Process a pending peg-out request
     * @dev Only authorized witnesses can call this function
     * @dev the processed request would be deleted from the pegOutRequests mapping
     * @param clientChain The client chain ID
     * @return nextRequest The next PegOutRequest
     * @custom:throws InvalidRequestStatus if the request status is not Pending
     * @custom:throws RequestNotFound if the request does not exist
     */
    function processNextPegOut(ClientChainID clientChain)
        external
        onlyAuthorizedWitness
        nonReentrant
        whenNotPaused
        returns (PegOutRequest memory nextRequest)
    {
        uint64 requestId = ++outboundNonce[clientChain];
        nextRequest = pegOutRequests[clientChain][requestId];

        // Check if the request exists
        if (nextRequest.requester == address(0)) {
            revert Errors.RequestNotFound(requestId);
        }

        // delete the request
        delete pegOutRequests[clientChain][requestId];

        // Emit event
        emit PegOutProcessed(
            uint8(nextRequest.withdrawType),
            clientChain,
            requestId,
            nextRequest.requester,
            nextRequest.clientChainAddress,
            nextRequest.amount
        );
    }

    /**
     * @notice Gets the client chain address for a given Exocore address
     * @param chainId The client chain ID
     * @param exocoreAddress The Exocore address
     * @return The client chain address
     */
    function getClientChainAddress(ClientChainID chainId, address exocoreAddress)
        external
        view
        returns (bytes memory)
    {
        return outboundRegistry[chainId][exocoreAddress];
    }

    /**
     * @notice Gets the Exocore address for a given client chain address
     * @param chainId The client chain ID
     * @param clientChainAddress The client chain address
     * @return The Exocore address
     */
    function getExocoreAddress(ClientChainID chainId, bytes calldata clientChainAddress)
        external
        view
        returns (address)
    {
        return inboundRegistry[chainId][clientChainAddress];
    }

    /**
     * @notice Gets the next inbound nonce for a given source chain ID.
     * @param srcChainId The source chain ID.
     * @return The next inbound nonce.
     */
    function nextInboundNonce(ClientChainID srcChainId) external view returns (uint64) {
        return inboundNonce[srcChainId] + 1;
    }

    /**
     * @notice Retrieves a PegOutRequest by client chain id and request id
     * @param clientChain The client chain ID
     * @param requestId The unique identifier of the request.
     * @return The PegOutRequest struct associated with the given requestId.
     */
    function getPegOutRequest(ClientChainID clientChain, uint64 requestId) public view returns (PegOutRequest memory) {
        return pegOutRequests[clientChain][requestId];
    }

    /**
     * @notice Retrieves the status of a transaction.
     * @param messageHash The hash of the transaction.
     * @return The status of the transaction.
     */
    function getTransactionStatus(bytes32 messageHash) public view returns (TxStatus) {
        return transactions[messageHash].status;
    }

    /**
     * @notice Retrieves the proof count of a transaction.
     * @param messageHash The hash of the transaction.
     * @return The proof count of the transaction.
     */
    function getTransactionProofCount(bytes32 messageHash) public view returns (uint256) {
        return transactions[messageHash].proofCount;
    }

    /**
     * @notice Retrieves the expiry time of a transaction.
     * @param messageHash The hash of the transaction.
     * @return The expiry time of the transaction.
     */
    function getTransactionExpiryTime(bytes32 messageHash) public view returns (uint256) {
        return transactions[messageHash].expiryTime;
    }

    /**
     * @notice Retrieves the witness time of a transaction.
     * @param messageHash The hash of the transaction.
     * @param witness The witness address.
     * @return The witness time of the transaction.
     */
    function getTransactionWitnessTime(bytes32 messageHash, address witness) public view returns (uint256) {
        return transactions[messageHash].witnessTime[witness];
    }

    function isConsensusRequired() external view returns (bool) {
        return _isConsensusRequired();
    }

    /**
     * @notice Checks if consensus is required for a stake message.
     * @return True if count of authorized witnesses is greater than or equal to REQUIRED_PROOFS, false otherwise.
     */
    function _isConsensusRequired() internal view returns (bool) {
        return authorizedWitnessCount >= requiredProofs;
    }

    /**
     * @notice Checks if a witness is authorized.
     * @param witness The witness address.
     * @return True if the witness is authorized, false otherwise.
     */
    function _isAuthorizedWitness(address witness) internal view returns (bool) {
        return authorizedWitnesses[witness];
    }

    function _addWitness(address _witness) internal {
        if (_witness == address(0)) {
            revert Errors.ZeroAddress();
        }
        if (_isAuthorizedWitness(_witness)) {
            revert Errors.WitnessAlreadyAuthorized(_witness);
        }

        bool wasConsensusRequired = _isConsensusRequired();

        authorizedWitnesses[_witness] = true;
        authorizedWitnessCount++;
        emit WitnessAdded(_witness);

        // Emit only when crossing the threshold from false to true
        if (!wasConsensusRequired && _isConsensusRequired()) {
            emit ConsensusActivated(requiredProofs, authorizedWitnessCount);
        }
    }

    /**
     * @notice Registers or updates the Bitcoin chain with the Exocore system.
     */
    function _registerOrUpdateClientChain(
        ClientChainID chainId,
        uint8 stakerAccountLength,
        string memory name,
        string memory metadata,
        string memory signatureScheme
    ) internal {
        uint32 chainIdUint32 = uint32(uint8(chainId));
        (bool success, bool updated) = ASSETS_CONTRACT.registerOrUpdateClientChain(
            chainIdUint32, stakerAccountLength, name, metadata, signatureScheme
        );
        if (!success) {
            revert Errors.RegisterClientChainToExocoreFailed(chainIdUint32);
        }
        if (updated) {
            emit ClientChainUpdated(chainIdUint32);
        } else {
            emit ClientChainRegistered(chainIdUint32);
        }
    }

    function _registerOrUpdateToken(
        ClientChainID chainId,
        bytes memory token,
        uint8 decimals,
        string memory name,
        string memory metadata,
        string memory oracleInfo
    ) internal {
        uint32 chainIdUint32 = uint32(uint8(chainId));
        bool registered = ASSETS_CONTRACT.registerToken(chainIdUint32, token, decimals, name, metadata, oracleInfo);
        if (!registered) {
            bool updated = ASSETS_CONTRACT.updateToken(chainIdUint32, token, metadata);
            if (!updated) {
                revert Errors.AddWhitelistTokenFailed(chainIdUint32, bytes32(token));
            }
            emit WhitelistTokenUpdated(chainIdUint32, VIRTUAL_TOKEN_ADDRESS);
        } else {
            emit WhitelistTokenAdded(chainIdUint32, VIRTUAL_TOKEN_ADDRESS);
        }
    }

    /**
     * @notice Verifies the signature of a stake message.
     * @param signer The signer address.
     * @param _msg The stake message.
     * @param signature The signature to verify.
     */
    function _verifySignature(address signer, StakeMsg calldata _msg, bytes memory signature)
        internal
        pure
        returns (bytes32 messageHash)
    {
        // StakeMsg, EIP721 is preferred next step.
        bytes memory encodeMsg = abi.encode(
            _msg.chainId, _msg.srcAddress, _msg.exocoreAddress, _msg.operator, _msg.amount, _msg.nonce, _msg.txTag
        );
        messageHash = keccak256(encodeMsg);

        SignatureVerifier.verifyMsgSig(signer, messageHash, signature);
    }

    /**
     * @dev Verifies that all required fields in StakeMsg are valid
     * @param _msg The stake message to verify
     */
    function _verifyStakeMsgFields(StakeMsg calldata _msg) internal pure {
        // Combine all non-zero checks into a single value
        uint256 nonZeroCheck =
            uint8(_msg.chainId) | _msg.srcAddress.length | _msg.amount | _msg.nonce | _msg.txTag.length;

        if (nonZeroCheck == 0) {
            revert Errors.InvalidStakeMessage();
        }

        if (bytes(_msg.operator).length > 0 && !isValidOperatorAddress(_msg.operator)) {
            revert Errors.InvalidOperator();
        }
    }

    function _verifyTxTagNotProcessed(ClientChainID chainId, bytes calldata txTag) internal view {
        if (processedClientChainTxs[chainId][txTag]) {
            revert Errors.TxTagAlreadyProcessed();
        }
    }

    /**
     * @notice Verifies a stake message.
     * @param witness The witness address that signed the message.
     * @param _msg The stake message.
     * @param signature The signature to verify.
     */
    function _verifyStakeMessage(address witness, StakeMsg calldata _msg, bytes calldata signature)
        internal
        view
        returns (bytes32 messageHash)
    {
        // verify that the stake message fields are valid
        _verifyStakeMsgFields(_msg);

        // Verify nonce
        _verifyInboundNonce(_msg.chainId, _msg.nonce);

        // Verify that the txTag has not been processed
        _verifyTxTagNotProcessed(_msg.chainId, _msg.txTag);

        // Verify signature
        messageHash = _verifySignature(witness, _msg, signature);
    }

    /**
     * @notice Initiates a peg-out request for a given token amount to a Bitcoin address
     * @dev This function creates a new peg-out request and stores it in the contract's state
     * @param clientChain The client chain to be pegged out
     * @param _amount The amount of tokens to be pegged out
     * @param withdrawer The Exocore address associated with the Bitcoin address
     * @param _withdrawType The type of withdrawal (e.g., normal, fast)
     * @return requestId The unique identifier for the peg-out request
     * @custom:throws RequestAlreadyExists if a request with the same parameters already exists
     */
    function _initiatePegOut(
        ClientChainID clientChain,
        uint256 _amount,
        address withdrawer,
        bytes memory clientChainAddress,
        WithdrawType _withdrawType
    ) internal returns (uint64 requestId) {
        // 2. increase the peg-out nonce for the client chain and return as requestId
        requestId = ++pegOutNonce[clientChain];

        // 3. Check if request already exists
        PegOutRequest storage request = pegOutRequests[clientChain][requestId];
        if (request.requester != address(0)) {
            revert Errors.RequestAlreadyExists(uint32(uint8(clientChain)), requestId);
        }

        // 4. Create new PegOutRequest
        request.chainId = clientChain;
        request.nonce = requestId;
        request.requester = withdrawer;
        request.clientChainAddress = clientChainAddress;
        request.amount = _amount;
        request.withdrawType = _withdrawType;
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
        ClientChainID clientChainId,
        bytes memory srcAddress,
        address depositorExoAddr,
        uint256 amount,
        bytes memory txTag
    ) internal {
        (bool success, uint256 updatedBalance) = ASSETS_CONTRACT.depositLST(
            uint32(uint8(clientChainId)), VIRTUAL_TOKEN, depositorExoAddr.toExocoreBytes(), amount
        );
        if (!success) {
            revert Errors.DepositFailed(txTag);
        }

        emit DepositCompleted(clientChainId, txTag, depositorExoAddr, srcAddress, amount, updatedBalance);
    }

    /**
     * @notice Internal function to delegate BTC like token.
     * @param clientChainId The client chain ID.
     * @param delegator The Exocore address.
     * @param operator The operator's address.
     * @param amount The amount to delegate.
     * @return success True if the delegation was successful, false otherwise.
     * @dev Sometimes we may not want to revert on failure, so we return a boolean.
     */
    function _delegate(ClientChainID clientChainId, address delegator, string memory operator, uint256 amount)
        internal
        returns (bool success)
    {
        uint64 nonce = ++delegationNonce[clientChainId];
        success = DELEGATION_CONTRACT.delegate(
            uint32(uint8(clientChainId)), nonce, VIRTUAL_TOKEN, delegator.toExocoreBytes(), bytes(operator), amount
        );
    }

    function _revokeTxIfExpired(bytes32 txid) internal {
        Transaction storage txn = transactions[txid];
        if (txn.status == TxStatus.Pending && block.timestamp >= txn.expiryTime) {
            txn.status = TxStatus.Expired;
            emit TransactionExpired(txid);
        }
    }

    function _registerAddress(ClientChainID chainId, bytes memory depositor, address exocoreAddress) internal {
        require(depositor.length > 0 && exocoreAddress != address(0), "Invalid address");
        require(inboundRegistry[chainId][depositor] == address(0), "Depositor address already registered");
        require(outboundRegistry[chainId][exocoreAddress].length == 0, "Exocore address already registered");

        inboundRegistry[chainId][depositor] = exocoreAddress;
        outboundRegistry[chainId][exocoreAddress] = depositor;

        emit AddressRegistered(chainId, depositor, exocoreAddress);
    }

    function _processStakeMsg(StakeMsg memory _msg) internal {
        // increment inbound nonce for the client chain and mark the tx as processed
        inboundNonce[_msg.chainId]++;
        processedClientChainTxs[_msg.chainId][_msg.txTag] = true;

        // register address if not already registered
        if (
            inboundRegistry[_msg.chainId][_msg.srcAddress] == address(0)
                && outboundRegistry[_msg.chainId][_msg.exocoreAddress].length == 0
        ) {
            if (_msg.exocoreAddress == address(0)) {
                revert Errors.ZeroAddress();
            }
            _registerAddress(_msg.chainId, _msg.srcAddress, _msg.exocoreAddress);
        }

        address stakerExoAddr = inboundRegistry[_msg.chainId][_msg.srcAddress];
        uint256 fee = _msg.amount * bridgeFeeRate / BASIS_POINTS;
        uint256 amountAfterFee = _msg.amount - fee;

        // we use registered exocore address as the depositor
        // this should always succeed and never revert, otherwise something is wrong.
        _deposit(_msg.chainId, _msg.srcAddress, stakerExoAddr, amountAfterFee, _msg.txTag);

        // delegate to operator if operator is provided, and do not revert if it fails since we need to count the stake
        // as deposited
        if (bytes(_msg.operator).length > 0) {
            bool success = _delegate(_msg.chainId, stakerExoAddr, _msg.operator, amountAfterFee);
            if (!success) {
                emit DelegationFailedForStake(_msg.chainId, stakerExoAddr, _msg.operator, amountAfterFee);
            } else {
                emit DelegationCompleted(_msg.chainId, stakerExoAddr, _msg.operator, amountAfterFee);
            }
        }

        emit StakeMsgExecuted(_msg.chainId, _msg.nonce, stakerExoAddr, amountAfterFee);
    }

}
