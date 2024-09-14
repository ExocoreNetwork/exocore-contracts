pragma solidity ^0.8.19;

import {IExocoreGateway} from "src/interfaces/IExocoreGateway.sol";
import {Action} from "src/storage/GatewayStorage.sol";

import {IAssets} from "src/interfaces/precompiles/IAssets.sol";
import {IClaimReward} from "src/interfaces/precompiles/IClaimReward.sol";
import {IDelegation} from "src/interfaces/precompiles/IDelegation.sol";

import {
    MessagingFee,
    MessagingReceipt,
    OAppReceiverUpgradeable,
    OAppUpgradeable,
    Origin
} from "src/lzApp/OAppUpgradeable.sol";
import {ExocoreGatewayStorage} from "src/storage/ExocoreGatewayStorage.sol";

import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {ILayerZeroReceiver} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroReceiver.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {Errors} from "src/libraries/Errors.sol";
import {OAppCoreUpgradeable} from "src/lzApp/OAppCoreUpgradeable.sol";

contract ExocoreGatewayMock is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    IExocoreGateway,
    ExocoreGatewayStorage,
    OAppUpgradeable
{

    using OptionsBuilder for bytes;

    address public immutable ASSETS_PRECOMPILE_ADDRESS;
    address public immutable CLAIM_REWARD_PRECOMPILE_ADDRESS;
    address public immutable DELEGATION_PRECOMPILE_ADDRESS;

    IAssets internal immutable ASSETS_CONTRACT;
    IClaimReward internal immutable CLAIM_REWARD_CONTRACT;
    IDelegation internal immutable DELEGATION_CONTRACT;

    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "ExocoreGateway: can only be called from this contract itself with a low-level call"
        );
        _;
    }

    constructor(
        address endpoint_,
        address assetsPrecompileMock,
        address ClaimRewardPrecompileMock,
        address delegationPrecompileMock
    ) OAppUpgradeable(endpoint_) {
        require(endpoint_ != address(0), "Endpoint address cannot be zero.");
        require(assetsPrecompileMock != address(0), "Assets precompile address cannot be zero.");
        require(ClaimRewardPrecompileMock != address(0), "ClaimReward precompile address cannot be zero.");
        require(delegationPrecompileMock != address(0), "Delegation precompile address cannot be zero.");

        ASSETS_PRECOMPILE_ADDRESS = assetsPrecompileMock;
        CLAIM_REWARD_PRECOMPILE_ADDRESS = ClaimRewardPrecompileMock;
        DELEGATION_PRECOMPILE_ADDRESS = delegationPrecompileMock;

        ASSETS_CONTRACT = IAssets(ASSETS_PRECOMPILE_ADDRESS);
        CLAIM_REWARD_CONTRACT = IClaimReward(CLAIM_REWARD_PRECOMPILE_ADDRESS);
        DELEGATION_CONTRACT = IDelegation(DELEGATION_PRECOMPILE_ADDRESS);

        _disableInitializers();
    }

    receive() external payable {}

    /// @notice Initializes the ExocoreGateway contract.
    /// @param owner_ The address of the contract owner.
    function initialize(address owner_) external initializer {
        if (owner_ == address(0)) {
            revert Errors.ZeroAddress();
        }

        _initializeWhitelistFunctionSelectors();
        _transferOwnership(owner_);
        __OAppCore_init_unchained(owner_);
        __Pausable_init_unchained();
        __ReentrancyGuard_init_unchained();
    }

    /// @dev Initializes the whitelist function selectors.
    function _initializeWhitelistFunctionSelectors() private {
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT_LST] = this.handleDepositMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT_NST] = this.handleDepositMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_LST] = this.handleWithdrawalMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_NST] = this.handleWithdrawalMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_CLAIM_REWARD] = this.handleRewardMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.handleDelegationMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.handleDelegationMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO] =
            this.handleDepositThenDelegateMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_ASSOCIATE_OPERATOR] = this.handleAssociationMessage.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DISSOCIATE_OPERATOR] = this.handleAssociationMessage.selector;
    }

    /// @notice Pauses the contract.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Sends a request to mark the bootstrap on a chain.
    /// @param chainIndex The index of the chain.
    /// @dev This function is useful if the bootstrap failed on a chain and needs to be retried.
    function markBootstrap(uint32 chainIndex) public payable whenNotPaused nonReentrant {
        _markBootstrap(chainIndex);
    }

    /// @dev Internal function to mark the bootstrap on a chain.
    /// @param chainIndex The index of the chain.
    function _markBootstrap(uint32 chainIndex) internal {
        // we don't track that a request was sent to a chain to allow for retrials
        // if the transaction fails on the destination chain
        _sendInterchainMsg(chainIndex, Action.REQUEST_MARK_BOOTSTRAP, "", false);
        emit BootstrapRequestSent(chainIndex);
    }

    /// @inheritdoc IExocoreGateway
    function registerOrUpdateClientChain(
        uint32 clientChainId,
        bytes32 peer,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) public onlyOwner whenNotPaused {
        if (
            clientChainId == uint32(0) || peer == bytes32(0) || addressLength == 0 || bytes(name).length == 0
                || bytes(metaInfo).length == 0
        ) {
            revert Errors.ZeroValue();
        }

        bool updated = _registerOrUpdateClientChain(clientChainId, addressLength, name, metaInfo, signatureType);
        // the peer is always set, regardless of `updated`
        super.setPeer(clientChainId, peer);

        if (updated) {
            emit ClientChainUpdated(clientChainId);
        } else {
            emit ClientChainRegistered(clientChainId);
        }
    }

    /// @notice Sets a peer on the destination chain for this contract.
    /// @dev This is the LayerZero peer. This function is here for the modifiers
    ///      as well as checking the registration of the client chain id.
    /// @param clientChainId The id of the client chain.
    /// @param clientChainGateway The address of the peer as bytes32.
    function setPeer(uint32 clientChainId, bytes32 clientChainGateway)
        public
        override(IOAppCore, OAppCoreUpgradeable)
        onlyOwner
        whenNotPaused
    {
        // This check, for the registration of the client chain id, is done here and
        // nowhere else. Elsewhere, the precompile is responsible for the checks.
        // The precompile is not called here at all, and hence, such a check must be
        // performed manually.
        _validateClientChainIdRegistered(clientChainId);
        super.setPeer(clientChainId, clientChainGateway);
    }

    /// @inheritdoc IExocoreGateway
    /// @notice Tokens can only be normal reward-bearing LST tokens like wstETH, rETH, jitoSol...
    /// And they are not intended to be: 1) rebasing tokens like stETH, since we assume staker's
    /// balance would not change if nothing is done after deposit, 2) fee-on-transfer tokens, since we
    /// assume Vault would account for the amount that staker transfers to it.
    /// @notice If we want to activate client chain's native restaking, we should add the corresponding virtual
    /// token address to the whitelist, bytes32(bytes20(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)) for Ethereum
    /// native restaking for example.
    function addWhitelistToken(
        uint32 clientChainId,
        bytes32 token,
        uint8 decimals,
        string calldata name,
        string calldata metaData,
        string calldata oracleInfo,
        uint128 tvlLimit
    ) external payable onlyOwner whenNotPaused nonReentrant {
        require(clientChainId != 0, "ExocoreGateway: client chain id cannot be zero");
        require(token != bytes32(0), "ExocoreGateway: token cannot be zero address");
        require(bytes(name).length != 0, "ExocoreGateway: name cannot be empty");
        require(bytes(metaData).length != 0, "ExocoreGateway: meta data cannot be empty");
        require(bytes(oracleInfo).length != 0, "ExocoreGateway: oracleInfo cannot be empty");
        // setting a tvl limit of 0 is psermitted to add an inactive token, which will be later
        // activated on the client chain

        bool success = ASSETS_CONTRACT.registerToken(
            clientChainId,
            abi.encodePacked(token), // convert to bytes from bytes32
            decimals,
            name,
            metaData,
            oracleInfo
        );
        if (success) {
            emit WhitelistTokenAdded(clientChainId, token);
            _sendInterchainMsg(
                clientChainId, Action.REQUEST_ADD_WHITELIST_TOKEN, abi.encodePacked(token, tvlLimit), false
            );
        } else {
            revert Errors.AddWhitelistTokenFailed(clientChainId, token);
        }
    }

    function updateWhitelistToken(uint32 clientChainId, bytes32 token, string calldata metaData)
        external
        onlyOwner
        whenNotPaused
        nonReentrant
    {
        require(clientChainId != 0, "ExocoreGateway: client chain id cannot be zero");
        require(token != bytes32(0), "ExocoreGateway: token cannot be zero address");
        require(bytes(metaData).length != 0, "ExocoreGateway: meta data cannot be empty");
        bool success = ASSETS_CONTRACT.updateToken(clientChainId, abi.encodePacked(token), metaData);
        if (success) {
            emit WhitelistTokenUpdated(clientChainId, token);
        } else {
            revert Errors.UpdateWhitelistTokenFailed(clientChainId, token);
        }
    }

    /**
     * @notice Associate an Exocore operator with an EVM staker(msg.sender),  and this would count staker's delegation
     * as operator's self-delegation when staker delegates to operator.
     * @param clientChainId The id of client chain
     * @param operator The Exocore operator address
     * @dev one staker(chainId+stakerAddress) can only associate one operator, while one operator might be associated
     * with multiple stakers
     */
    function associateOperatorWithEVMStaker(uint32 clientChainId, string calldata operator)
        external
        whenNotPaused
        isValidBech32Address(operator)
    {
        bytes memory staker = abi.encodePacked(bytes32(bytes20(msg.sender)));
        bool success = DELEGATION_CONTRACT.associateOperatorWithStaker(clientChainId, staker, bytes(operator));
        if (!success) {
            revert Errors.AssociateOperatorFailed(clientChainId, msg.sender, operator);
        }
    }

    /**
     * @notice Dissociate an Exocore operator from an EVM staker(msg.sender),  and this requires that the staker has
     * already been associated to operator.
     * @param clientChainId The id of client chain
     */
    function dissociateOperatorFromEVMStaker(uint32 clientChainId) external whenNotPaused {
        bytes memory staker = abi.encodePacked(bytes32(bytes20(msg.sender)));
        bool success = DELEGATION_CONTRACT.dissociateOperatorFromStaker(clientChainId, staker);
        if (!success) {
            revert Errors.DissociateOperatorFailed(clientChainId, msg.sender);
        }
    }

    /// @dev Validates that the client chain id is registered.
    /// @dev This is designed to be called only in the cases wherein the precompile isn't used.
    /// @dev In all other situations, it is the responsibility of the precompile to perform such
    ///      checks.
    /// @param clientChainId The client chain id.
    function _validateClientChainIdRegistered(uint32 clientChainId) internal view {
        (bool success, bool isRegistered) = ASSETS_CONTRACT.isRegisteredClientChain(clientChainId);
        if (!success) {
            revert Errors.ExocoreGatewayFailedToCheckClientChainId();
        }
        if (!isRegistered) {
            revert Errors.ExocoreGatewayNotRegisteredClientChainId();
        }
    }

    /// @dev The internal version of registerOrUpdateClientChain.
    /// @param clientChainId The client chain id.
    /// @param addressLength The length of the address type on the client chain.
    /// @param name The name of the client chain.
    /// @param metaInfo The arbitrary metadata for the client chain.
    /// @param signatureType The signature type supported by the client chain.
    function _registerOrUpdateClientChain(
        uint32 clientChainId,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) internal returns (bool) {
        (bool success, bool updated) =
            ASSETS_CONTRACT.registerOrUpdateClientChain(clientChainId, addressLength, name, metaInfo, signatureType);
        if (!success) {
            revert Errors.RegisterClientChainToExocoreFailed(clientChainId);
        }
        return updated;
    }

    /// @inheritdoc OAppReceiverUpgradeable
    function _lzReceive(Origin calldata _origin, bytes calldata message)
        internal
        virtual
        override
        whenNotPaused
        nonReentrant
    {
        _verifyAndUpdateNonce(_origin.srcEid, _origin.sender, _origin.nonce);
        _validateMessageLength(message);

        Action act = Action(uint8(message[0]));
        bytes calldata payload = message[1:];
        bytes4 selector_ = _whiteListFunctionSelectors[act];
        if (selector_ == bytes4(0)) {
            revert Errors.UnsupportedRequest(act);
        }

        (bool success, bytes memory responseOrReason) =
            address(this).call(abi.encodePacked(selector_, abi.encode(_origin.srcEid, _origin.nonce, act, payload)));
        if (!success) {
            revert Errors.RequestExecuteFailed(act, _origin.nonce, responseOrReason);
        }

        emit MessageExecuted(act, _origin.nonce);
    }

    /// @notice Responds to a deposit request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param act The action type.
    /// @param payload The request payload.
    function handleDepositMessage(uint32 srcChainId, uint64 lzNonce, Action act, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bool success;
        uint256 updatedBalance;
        bytes32 token =
            (act == Action.REQUEST_DEPOSIT_LST ? bytes32(payload[:32]) : bytes32(bytes20(VIRTUAL_NST_ADDRESS)));
        bytes calldata depositor = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        if (act == Action.REQUEST_DEPOSIT_LST) {
            (success, updatedBalance) =
                ASSETS_CONTRACT.depositLST(srcChainId, abi.encodePacked(token), depositor, amount);
        } else if (act == Action.REQUEST_DEPOSIT_NST) {
            bytes calldata validatorPubkey = payload[:32];
            (success, updatedBalance) =
                ASSETS_CONTRACT.depositNST(srcChainId, abi.encodePacked(validatorPubkey), depositor, amount);
        } else {
            revert Errors.MismatchMessageHanlder(); // should never happen though
        }

        if (!success) {
            revert Errors.DepositRequestShouldNotFail(srcChainId, lzNonce); // we should not let this happen
        }

        bytes memory response = abi.encodePacked(lzNonce, success, updatedBalance);

        _sendInterchainMsg(srcChainId, Action.RESPOND, response, true);

        emit DepositResult(true, token, bytes32(depositor), amount);
    }

    /// @notice Responds to a withdraw request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param act The action type.
    /// @param payload The request payload.
    function handleWithdrawalMessage(uint32 srcChainId, uint64 lzNonce, Action act, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bool success;
        uint256 updatedBalance;
        bytes32 token =
            (act == Action.REQUEST_WITHDRAW_LST ? bytes32(payload[:32]) : bytes32(bytes20(VIRTUAL_NST_ADDRESS)));
        bytes memory withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        if (act == Action.REQUEST_WITHDRAW_LST) {
            try ASSETS_CONTRACT.withdrawLST(srcChainId, abi.encodePacked(token), withdrawer, amount) returns (
                bool success_, uint256 updatedBalance_
            ) {
                success = success_;
                updatedBalance = updatedBalance_;
            } catch {
                emit ExocorePrecompileError(ASSETS_PRECOMPILE_ADDRESS, lzNonce);
            }
        } else if (act == Action.REQUEST_WITHDRAW_NST) {
            bytes calldata validatorPubkey = payload[:32];
            try ASSETS_CONTRACT.withdrawNST(srcChainId, abi.encodePacked(validatorPubkey), withdrawer, amount) returns (
                bool success_, uint256 updatedBalance_
            ) {
                success = success_;
                updatedBalance = updatedBalance_;
            } catch {
                emit ExocorePrecompileError(ASSETS_PRECOMPILE_ADDRESS, lzNonce);
            }
        } else {
            revert Errors.MismatchMessageHanlder(); // should never happen though
        }

        bytes memory response = abi.encodePacked(lzNonce, success, updatedBalance);
        _sendInterchainMsg(srcChainId, Action.RESPOND, response, true);

        emit WithdrawalResult(success, token, bytes32(withdrawer), amount);
    }

    /// @notice Responds to a reward request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param act The action type.
    /// @param payload The request payload.
    function handleRewardMessage(uint32 srcChainId, uint64 lzNonce, Action act, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bool success;
        uint256 updatedBalance;
        bytes calldata token = payload[:32];
        bytes calldata withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        try CLAIM_REWARD_CONTRACT.claimReward(srcChainId, token, withdrawer, amount) returns (
            bool success_, uint256 updatedBalance_
        ) {
            success = success_;
            updatedBalance = updatedBalance_;
        } catch {
            emit ExocorePrecompileError(CLAIM_REWARD_PRECOMPILE_ADDRESS, lzNonce);
        }

        bytes memory response = abi.encodePacked(lzNonce, success, updatedBalance);
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);

        emit ClaimRewardResult(success, bytes32(token), bytes32(withdrawer), amount);
    }

    /// @notice Responds to a delegate request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param act The action type.
    /// @param payload The request payload.
    function handleDelegationMessage(uint32 srcChainId, uint64 lzNonce, Action act, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bool requestQueued;
        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        if (act == Action.REQUEST_DELEGATE_TO) {
            try DELEGATION_CONTRACT.delegate(srcChainId, lzNonce, token, delegator, operator, amount) returns (
                bool requestQueued_
            ) {
                requestQueued = requestQueued_;
            } catch {
                emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            }
        } else if (act == Action.REQUEST_UNDELEGATE_FROM) {
            try DELEGATION_CONTRACT.undelegate(srcChainId, lzNonce, token, delegator, operator, amount) returns (
                bool requestQueued_
            ) {
                requestQueued = requestQueued_;
            } catch {
                emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            }
        } else {
            revert Errors.MismatchMessageHanlder(); // should never happen though
        }

        bytes memory response = abi.encodePacked(lzNonce, requestQueued);
        _sendInterchainMsg(srcChainId, Action.RESPOND, response, true);

        emit DelegationRequestReceived(
            requestQueued,
            act == Action.REQUEST_DELEGATE_TO,
            bytes32(token),
            bytes32(delegator),
            string(operator),
            amount
        );
    }

    /// @notice Responds to a deposit-then-delegate request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function handleDepositThenDelegateMessage(uint32 srcChainId, uint64 lzNonce, Action, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bool depositSuccess;
        bool delegateRequestQueued;
        uint256 updatedBalance;
        bytes memory token = payload[:32];
        bytes memory depositor = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        // while some of the code from requestDeposit and requestDelegateTo is duplicated here,
        // it is done intentionally to work around Solidity's limitations with regards to
        // function calls, error handling and indexing the return data of memory type.
        // for example, you cannot index a bytes memory result from the requestDepositTo call,
        // if you were to modify it to return bytes and then process them here.

        (depositSuccess, updatedBalance) = ASSETS_CONTRACT.depositLST(srcChainId, token, depositor, amount);
        if (!depositSuccess) {
            revert Errors.DepositRequestShouldNotFail(srcChainId, lzNonce); // we should not let this happen
        }
        emit DepositResult(true, bytes32(token), bytes32(depositor), amount);

        try DELEGATION_CONTRACT.delegate(srcChainId, lzNonce, token, depositor, operator, amount) returns (
            bool requestQueued_
        ) {
            delegateRequestQueued = requestQueued_;
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
        }
        emit DelegationRequestReceived(
            delegateRequestQueued, true, bytes32(token), bytes32(depositor), string(operator), amount
        );

        bytes memory response = abi.encodePacked(lzNonce, delegateRequestQueued, updatedBalance);
        _sendInterchainMsg(srcChainId, Action.RESPOND, response, true);
    }

    /// @notice Handles the associating operator request, and no response would be returned.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param act The action type.
    /// @param payload The request payload.
    function handleAssociationMessage(uint32 srcChainId, uint64 lzNonce, Action act, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bool success;
        bytes calldata staker = payload[:32];

        if (act == Action.REQUEST_ASSOCIATE_OPERATOR) {
            bytes calldata operator = payload[32:74];

            try DELEGATION_CONTRACT.associateOperatorWithStaker(srcChainId, staker, operator) returns (bool success_) {
                success = success_;
            } catch {
                emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            }
        } else if (act == Action.REQUEST_DISSOCIATE_OPERATOR) {
            try DELEGATION_CONTRACT.dissociateOperatorFromStaker(srcChainId, staker) returns (bool success_) {
                success = success_;
            } catch {
                emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            }
        } else {
            revert Errors.MismatchMessageHanlder(); // should never happen though
        }

        emit AssociationResult(success, act == Action.REQUEST_ASSOCIATE_OPERATOR, bytes32(staker));
    }

    /// @dev Sends an interchain message to the client chain.
    /// @param srcChainId The chain id of the source chain, from which a message was received, and to which a response
    /// is being sent.
    /// @param act The action to be performed.
    /// @param actionArgs The arguments for the action.
    /// @param payByApp If the source for the transaction funds is this contract.
    function _sendInterchainMsg(uint32 srcChainId, Action act, bytes memory actionArgs, bool payByApp)
        internal
        whenNotPaused
    {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(srcChainId, payload, options, false);

        address refundAddress = payByApp ? address(this) : msg.sender;
        MessagingReceipt memory receipt =
            _lzSend(srcChainId, payload, options, MessagingFee(fee.nativeFee, 0), refundAddress, payByApp);
        emit MessageSent(act, receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }

    /// @inheritdoc IExocoreGateway
    function quote(uint32 srcChainid, bytes calldata _message) public view returns (uint256 nativeFee) {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(srcChainid, _message, options, false);
        return fee.nativeFee;
    }

    /// @inheritdoc OAppReceiverUpgradeable
    function nextNonce(uint32 srcEid, bytes32 sender)
        public
        view
        virtual
        override(ILayerZeroReceiver, OAppReceiverUpgradeable)
        returns (uint64)
    {
        return inboundNonce[srcEid][sender] + 1;
    }

}
