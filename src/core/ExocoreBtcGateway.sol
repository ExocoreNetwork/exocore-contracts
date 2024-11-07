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
    function activateStakingForClientChain(ClientChainID clientChain_) external {
        if (clientChain_ == ClientChainID.Bitcoin) {
            _registerOrUpdateClientChain(
                clientChain_,
                STAKER_ACCOUNT_LENGTH,
                BITCOIN_NAME,
                BITCOIN_METADATA,
                BITCOIN_SIGNATURE_SCHEME
            );
            _registerOrUpdateToken(
                clientChain_,
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
     * @notice Registers a BTC address with an Exocore address.
     * @param depositor The BTC address to register.
     * @param exocoreAddress The corresponding Exocore address.
     * @dev Can only be called by an authorized witness.
     */
    function registerAddress(bytes calldata depositor, address exocoreAddress) external onlyAuthorizedWitness {
        _registerAddress(depositor, exocoreAddress);
    }

    /**
     * @notice Submits a proof for a stake message.
     * @notice The submitted message would be processed after collecting enough proofs from withnesses.
     * @param _message The interchain message.
     * @param _signature The signature of the message.
     */
    function submitProofForStakeMsg(StakeMsg calldata _message, bytes calldata _signature)
        external
        nonReentrant
        whenNotPaused
    {
        bytes32 messageHash = _verifyStakeMessage(_message, _signature);

        // we should revoke the tx by setting it as expired if it has expired
        _revokeTxIfExpired(messageHash);

        Transaction storage txn = transactions[messageHash];

        if (txn.status == TxStatus.Pending) {
            // if the witness has already submitted proof at or after the start of the proof window, they cannot submit again
            if (txn.witnessTime[msg.sender] >= txn.expiryTime - PROOF_TIMEOUT) {
                revert Errors.WitnessAlreadySubmittedProof();
            }
            txn.witnessTime[msg.sender] = block.timestamp;
            txn.proofCount++;
        } else {
            txn.status = TxStatus.Pending;
            txn.expiryTime = block.timestamp + PROOF_TIMEOUT;
            txn.proofCount = 1;
            txn.witnessTime[msg.sender] = block.timestamp;
            txn.stakeMsg = _message;
        }

        emit ProofSubmitted(messageHash, msg.sender, _message);

        // Check for consensus
        if (txn.proofCount >= REQUIRED_PROOFS) {
            _processStakeMsg(txn.stakeMsg);
            delete transactions[messageHash];
        }
    }

    /**
     * @notice Deposits BTC to the Exocore system.
     * @param _msg The interchain message containing the deposit details.
     * @param signature The signature to verify.
     */
    function processStakeMessage(StakeMsg calldata _msg, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isValidAmount(_msg.amount)
        onlyAuthorizedWitness
    {
        require(authorizedWitnesses[msg.sender], "Not an authorized witness");
        _verifyStakeMessage(_msg, signature);

        _processStakeMsg(_msg);
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
        ClientChainID chainId = ClientChainID(uint8(token));
        bool success = _delegate(chainId, msg.sender, operator, amount);
        if (!success) {
            revert DelegationFailed();
        }

        emit DelegationCompleted(chainId, msg.sender, operator, amount);
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
        ClientChainID chainId = ClientChainID(uint8(token));
        uint64 nonce = ++delegationNonce[chainId][msg.sender];
        bool success = DELEGATION_CONTRACT.undelegate(uint32(uint8(chainId)), nonce, VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), bytes(operator), amount);
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
        ClientChainID chainId = ClientChainID(uint8(token));
        (bool success, uint256 updatedBalance) =
            ASSETS_CONTRACT.withdrawLST(uint32(uint8(chainId)), VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), amount);
        if (!success) {
            revert WithdrawPrincipalFailed();
        }

        (uint64 requestId, bytes memory clientChainAddress) =
            _initiatePegOut(chainId, amount, msg.sender, WithdrawType.WithdrawPrincipal);
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
        ClientChainID chainId = ClientChainID(uint8(token));
        (bool success, uint256 updatedBalance) =
            REWARD_CONTRACT.claimReward(uint32(uint8(chainId)), VIRTUAL_TOKEN, msg.sender.toExocoreBytes(), amount);
        if (!success) {
            revert WithdrawRewardFailed();
        }
        (uint64 requestId, bytes memory clientChainAddress) =
            _initiatePegOut(chainId, amount, msg.sender, WithdrawType.WithdrawReward);

        emit WithdrawRewardRequested(chainId, requestId, msg.sender, clientChainAddress, amount, updatedBalance);
    }

    /**
     * @notice Process a pending peg-out request
     * @dev Only authorized witnesses can call this function
     * @custom:throws InvalidRequestStatus if the request status is not Pending
     * @custom:throws RequestNotFound if the request does not exist
     */
    function processNextPegOut(ClientChainID clientChain)
        external
        onlyAuthorizedWitness
        nonReentrant
        whenNotPaused
        returns (uint64 requestId)
    {
        requestId = ++outboundNonce[clientChain];
        PegOutRequest storage request = pegOutRequests[requestId];

        // Check if the request exists
        if (request.requester == address(0)) {
            revert RequestNotFound(requestId);
        }

        // delete the request
        delete pegOutRequests[requestId];

        // Emit event
        emit PegOutProcessed(requestId);
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
     * @return The current nonce.
     */
    function nextInboundNonce(ClientChainID srcChainId) external view returns (uint64) {
        return inboundNonce[srcChainId]+1;
    }

    /**
     * @notice Retrieves a PegOutRequest by its requestId.
     * @param requestId The unique identifier of the request.
     * @return The PegOutRequest struct associated with the given requestId.
     */
    function getPegOutRequest(uint64 requestId) public view returns (PegOutRequest memory) {
        return pegOutRequests[requestId];
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
    function _registerOrUpdateClientChain(ClientChainID chainId, uint8 stakerAccountLength, string memory name, string memory metadata, string memory signatureScheme) internal {
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

    function _registerOrUpdateToken(ClientChainID chainId, bytes memory token, uint8 decimals, string memory name, string memory metadata, string memory oracleInfo) internal {
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
     * @notice Verifies the signature of an interchain message.
     * @param _msg The interchain message.
     * @param signature The signature to verify.
     */
    function _verifySignature(StakeMsg calldata _msg, bytes memory signature) internal view returns (bytes32 messageHash) {
        // StakeMsg, EIP721 is preferred next step.
        bytes memory encodeMsg = abi.encode(
            _msg.chainId,
            _msg.srcAddress,
            _msg.operator,
            _msg.amount,
            _msg.nonce,
            _msg.txTag
        );
        messageHash = keccak256(encodeMsg);

        SignatureVerifier.verifyMsgSig(msg.sender, messageHash, signature);
    }

    /**
     * @dev Verifies that all required fields in StakeMsg are valid
     * @param _msg The stake message to verify
     */
    function _verifyStakeMsgFields(StakeMsg calldata _msg) internal pure {
        // Combine all non-zero checks into a single value
        uint256 validityCheck = uint8(_msg.chainId) 
            | _msg.srcAddress.length 
            | _msg.amount
            | _msg.nonce 
            | _msg.txTag.length;
            
        if (validityCheck == 0) revert Errors.InvalidStakeMessage();
    }

    function _verifyTxTagNotProcessed(bytes calldata txTag) internal view {
        if (processedBtcTxs[txTag].processed) {
            revert Errors.TxTagAlreadyProcessed();
        }
    }

    /**
     * @notice Verifies a stake message.
     * @param _msg The stake message.
     * @param signature The signature to verify.
     */
    function _verifyStakeMessage(StakeMsg calldata _msg, bytes calldata signature)
        internal
        view
        returns (bytes32 messageHash)
    {
        // verify that the stake message fields are valid
        _verifyStakeMsgFields(_msg);

        // Verify nonce
        _verifyInboundNonce(_msg.chainId, _msg.nonce);

        // Verify that the txTag has not been processed
        _verifyTxTagNotProcessed(_msg.txTag);

        // Verify signature
        messageHash = _verifySignature(_msg, signature);
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
    function _initiatePegOut(ClientChainID clientChain, uint256 _amount, address withdrawer, WithdrawType _withdrawType)
        internal
        returns (uint64 requestId, bytes memory clientChainAddress)
    {        

        // 1. Check client c address
        clientChainAddress = exocoreToBtcAddress[withdrawer];
        if (clientChainAddress.length == 0) {
            revert BtcAddressNotRegistered();
        }

        // 2. increase the peg-out nonce for the client chain and return as requestId
        requestId = ++pegOutNonce[clientChain];

        // 3. Check if request already exists
        PegOutRequest storage request = pegOutRequests[requestId];
        if (request.requester != address(0)) {
            revert RequestAlreadyExists(requestId);
        }

        // 4. Create new PegOutRequest
        request.chainId = clientChain;
        request.requester = withdrawer;
        request.clientChainAddress = clientChainAddress;
        request.amount = _amount;
        request.withdrawType = _withdrawType;
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
        ClientChainID clientChainId,
        bytes memory srcAddress,
        address depositorExoAddr,
        uint256 amount,
        bytes memory txTag
    ) internal {
        (bool success, uint256 updatedBalance) =
            ASSETS_CONTRACT.depositLST(uint32(uint8(clientChainId)), VIRTUAL_TOKEN, depositorExoAddr.toExocoreBytes(), amount);
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
     * @return success True if the delegation was successful, false otherwise.
     * @dev Sometimes we may not want to revert on failure, so we return a boolean.
     */
    function _delegate(
        ClientChainID clientChainId,
        address delegator,
        string memory operator,
        uint256 amount
    ) internal returns(bool success){
        uint64 nonce = ++delegationNonce[clientChainId][delegator];
        success = DELEGATION_CONTRACT.delegate(uint32(uint8(clientChainId)), nonce, VIRTUAL_TOKEN, delegator.toExocoreBytes(), bytes(operator), amount);
    }

    function _revokeTxIfExpired(bytes32 txid) internal {
        Transaction storage txn = transactions[txid];
        if (txn.status == TxStatus.Pending && block.timestamp >= txn.expiryTime) {
            txn.status = TxStatus.Expired;
            emit TransactionExpired(txid);
        }
    }

    function _registerAddress(bytes memory depositor, address exocoreAddress) internal {
        require(depositor.length > 0 && exocoreAddress != address(0), "Invalid address");
        require(btcToExocoreAddress[depositor] != address(0), "Depositor address already registered");
        require(exocoreToBtcAddress[exocoreAddress].length == 0, "Exocore address already registered");

        btcToExocoreAddress[depositor] = exocoreAddress;
        exocoreToBtcAddress[exocoreAddress] = depositor;

        emit AddressRegistered(depositor, exocoreAddress);
    }

    function _processStakeMsg(StakeMsg memory _msg) internal {
        // increment inbound nonce for the client chain and mark the tx as processed
        inboundNonce[_msg.chainId]++;
        processedBtcTxs[_msg.txTag] = TxInfo(true, block.timestamp);

        // register address if not already registered
        if (btcToExocoreAddress[_msg.srcAddress] == address(0) && exocoreToBtcAddress[_msg.exocoreAddress].length == 0) {
            if (_msg.exocoreAddress == address(0)) {
                revert Errors.ZeroAddress();
            }
            _registerAddress(_msg.srcAddress, _msg.exocoreAddress);
        }

        address stakerExoAddr = btcToExocoreAddress[_msg.srcAddress];
        uint256 fee = _msg.amount * bridgeFee;
        uint256 amountAfterFee = _msg.amount - fee;

        // we use registered exocore address as the depositor
        // this should always succeed and never revert, otherwise something is wrong.
        _deposit(_msg.chainId, _msg.srcAddress, stakerExoAddr, amountAfterFee, _msg.txTag);

        // delegate to operator if operator is provided, and do not revert if it fails since we need to count the stake as deposited
        if (bytes(_msg.operator).length > 0) {
            bool success = _delegate(_msg.chainId, stakerExoAddr, _msg.operator, amountAfterFee);
            if (!success) {
                emit DelegationFailedForStake(_msg.chainId, stakerExoAddr, _msg.operator, amountAfterFee);
            } else {
                emit DelegationCompleted(_msg.chainId, stakerExoAddr, _msg.operator, amountAfterFee);
            }
        }
    }

}
