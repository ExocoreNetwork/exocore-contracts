// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IExocoreGateway} from "../interfaces/IExocoreGateway.sol";

import {ASSETS_CONTRACT, ASSETS_PRECOMPILE_ADDRESS} from "../interfaces/precompiles/IAssets.sol";
import {CLAIM_REWARD_CONTRACT, CLAIM_REWARD_PRECOMPILE_ADDRESS} from "../interfaces/precompiles/IClaimReward.sol";
import {DELEGATION_CONTRACT, DELEGATION_PRECOMPILE_ADDRESS} from "../interfaces/precompiles/IDelegation.sol";

import {
    MessagingFee,
    MessagingReceipt,
    OAppReceiverUpgradeable,
    OAppUpgradeable,
    Origin
} from "../lzApp/OAppUpgradeable.sol";
import {ExocoreGatewayStorage} from "../storage/ExocoreGatewayStorage.sol";

import {Errors} from "../libraries/Errors.sol";
import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {ILayerZeroReceiver} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroReceiver.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/// @title ExocoreGateway
/// @author ExocoreNetwork
/// @notice The gateway contract deployed on Exocore chain for client chain operations.
/// @dev This contract address must be registered in the `x/assets` module for the precompile operations to go through.
contract ExocoreGateway is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    IExocoreGateway,
    ExocoreGatewayStorage,
    OAppUpgradeable
{

    using OptionsBuilder for bytes;

    /// @dev Ensures that the function is called only from this contract via low-level call.
    modifier onlyCalledFromThis() {
        if (msg.sender != address(this)) {
            revert Errors.ExocoreGatewayOnlyCalledFromThis();
        }
        _;
    }

    /// @notice Creates the ExocoreGateway contract.
    /// @param endpoint_ The LayerZero endpoint address deployed on this chain
    constructor(address endpoint_) OAppUpgradeable(endpoint_) {
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
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = this.requestDeposit.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.requestDelegateTo.selector;
        _whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.requestUndelegateFrom.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE] =
            this.requestWithdrawPrincipal.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] = this.requestWithdrawReward.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO] =
            this.requestDepositThenDelegateTo.selector;
        _whiteListFunctionSelectors[Action.REQUEST_ASSOCIATE_OPERATOR] =
            this.requestAssociateOperatorWithStaker.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DISSOCIATE_OPERATOR] =
            this.requestDissociateOperatorFromStaker.selector;
    }

    /// @notice Pauses the contract.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Marks the bootstrap on all chains.
    /// @dev This function obtains a list of client chain ids from the precompile, and then
    /// sends a `REQUEST_MARK_BOOTSTRAP` to all of them. In response, the Bootstrap contract
    /// on those chains should upgrade itself to the ClientChainGateway contract.
    /// This function should be the first to be called after the LZ infrastructure is ready.
    // TODO: call this function automatically, either within the initializer (which requires
    // setPeer) or be triggered by Golang after the contract is deployed.
    // For manual calls, this function should be called immediately after deployment and
    // then never needs to be called again.
    function markBootstrapOnAllChains() public whenNotPaused nonReentrant {
        (bool success, uint32[] memory chainIndices) = ASSETS_CONTRACT.getClientChains();
        if (!success) {
            revert Errors.ExocoreGatewayFailedToGetClientChainIds();
        }
        for (uint256 i = 0; i < chainIndices.length; ++i) {
            uint32 chainIndex = chainIndices[i];
            if (!chainToBootstrapped[chainIndex]) {
                _sendInterchainMsg(chainIndex, Action.REQUEST_MARK_BOOTSTRAP, "", true);
                // TODO: should this be marked only upon receiving a response?
                chainToBootstrapped[chainIndex] = true;
                emit BootstrapRequestSent(chainIndex);
            }
        }
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
        uint256 tvlLimit,
        string calldata name,
        string calldata metaData,
        string calldata oracleInfo
    ) external payable onlyOwner whenNotPaused nonReentrant {
        if (msg.value == 0) {
            revert Errors.ZeroValue();
        }
        require(clientChainId != 0, "ExocoreGateway: client chain id cannot be zero");
        require(token != bytes32(0), "ExocoreGateway: token cannot be zero address");
        require(tvlLimit > 0, "ExocoreGateway: tvl limit should not be zero");
        require(bytes(name).length != 0, "ExocoreGateway: name cannot be empty");
        require(bytes(metaData).length != 0, "ExocoreGateway: meta data cannot be empty");
        require(bytes(oracleInfo).length != 0, "ExocoreGateway: oracleInfo cannot be empty");

        bool success = ASSETS_CONTRACT.registerToken(
            clientChainId,
            abi.encodePacked(token), // convert to bytes from bytes32
            decimals,
            tvlLimit,
            name,
            metaData,
            oracleInfo
        );
        if (success) {
            emit WhitelistTokenAdded(clientChainId, token);
            _sendInterchainMsg(
                clientChainId,
                Action.REQUEST_ADD_WHITELIST_TOKEN,
                abi.encodePacked(token), // convert for decoding it on the receiving end
                false
            );
        } else {
            revert AddWhitelistTokenFailed(clientChainId, token);
        }
    }

    /// @inheritdoc IExocoreGateway
    function updateWhitelistToken(uint32 clientChainId, bytes32 token, uint256 tvlLimit, string calldata metaData)
        external
        onlyOwner
        whenNotPaused
        nonReentrant
    {
        require(clientChainId != 0, "ExocoreGateway: client chain id cannot be zero");
        require(token != bytes32(0), "ExocoreGateway: token cannot be zero address");
        // setting tvlLimit to 0 is allowed as a way to disable the token
        require(bytes(metaData).length != 0, "ExocoreGateway: meta data cannot be empty");
        bool success = ASSETS_CONTRACT.updateToken(clientChainId, abi.encodePacked(token), tvlLimit, metaData);
        if (success) {
            emit WhitelistTokenUpdated(clientChainId, token);
        } else {
            revert UpdateWhitelistTokenFailed(clientChainId, token);
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
            revert RegisterClientChainToExocoreFailed(clientChainId);
        }
        return updated;
    }

    /// @inheritdoc OAppReceiverUpgradeable
    function _lzReceive(Origin calldata _origin, bytes calldata payload)
        internal
        virtual
        override
        whenNotPaused
        nonReentrant
    {
        _verifyAndUpdateNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        bytes4 selector_ = _whiteListFunctionSelectors[act];
        if (selector_ == bytes4(0)) {
            revert UnsupportedRequest(act);
        }

        (bool success, bytes memory responseOrReason) =
            address(this).call(abi.encodePacked(selector_, abi.encode(_origin.srcEid, _origin.nonce, payload[1:])));
        if (!success) {
            revert RequestExecuteFailed(act, _origin.nonce, responseOrReason);
        }
    }

    /// @notice Responds to a deposit request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestDeposit(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _validatePayloadLength(payload, DEPOSIT_REQUEST_LENGTH, Action.REQUEST_DEPOSIT);

        bytes memory token = payload[:32];
        bytes memory depositor = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, uint256 updatedBalance) = ASSETS_CONTRACT.depositTo(srcChainId, token, depositor, amount);
        if (!success) {
            revert DepositRequestShouldNotFail(srcChainId, lzNonce);
        }

        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);

        emit DepositResult(true, bytes32(token), bytes32(depositor), amount);
    }

    /// @notice Responds to a withdraw-principal request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestWithdrawPrincipal(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(
            payload, WITHDRAW_PRINCIPAL_REQUEST_LENGTH, Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE
        );

        bytes memory token = payload[:32];
        bytes memory withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        bool result = false;
        try ASSETS_CONTRACT.withdrawPrincipal(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            result = success;
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);
        } catch {
            emit ExocorePrecompileError(ASSETS_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)), true);
        }

        emit WithdrawPrincipalResult(result, bytes32(token), bytes32(withdrawer), amount);
    }

    /// @notice Responds to a withdraw-reward request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestWithdrawReward(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, CLAIM_REWARD_REQUEST_LENGTH, Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE);

        bytes memory token = payload[:32];
        bytes memory withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        bool result = false;
        try CLAIM_REWARD_CONTRACT.claimReward(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            result = success;
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);
        } catch {
            emit ExocorePrecompileError(CLAIM_REWARD_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)), true);
        }

        emit WithdrawRewardResult(result, bytes32(token), bytes32(withdrawer), amount);
    }

    /// @notice Responds to a delegate request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _validatePayloadLength(payload, DELEGATE_REQUEST_LENGTH, Action.REQUEST_DELEGATE_TO);

        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        bool result = false;
        try DELEGATION_CONTRACT.delegateToThroughClientChain(srcChainId, lzNonce, token, delegator, operator, amount)
        returns (bool success) {
            result = success;
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success), true);
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false), true);
        }

        emit DelegateResult(result, bytes32(token), bytes32(delegator), string(operator), amount);
    }

    /// @notice Responds to an undelegate request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestUndelegateFrom(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, UNDELEGATE_REQUEST_LENGTH, Action.REQUEST_UNDELEGATE_FROM);

        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        bool result = false;
        try DELEGATION_CONTRACT.undelegateFromThroughClientChain(
            srcChainId, lzNonce, token, delegator, operator, amount
        ) returns (bool success) {
            result = success;
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success), true);
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false), true);
        }

        emit UndelegateResult(result, bytes32(token), bytes32(delegator), string(operator), amount);
    }

    /// @notice Responds to a deposit-then-delegate request from a client chain.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestDepositThenDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH, Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO);

        bytes memory token = payload[:32];
        bytes memory depositor = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        // while some of the code from requestDeposit and requestDelegateTo is duplicated here,
        // it is done intentionally to work around Solidity's limitations with regards to
        // function calls, error handling and indexing the return data of memory type.
        // for example, you cannot index a bytes memory result from the requestDepositTo call,
        // if you were to modify it to return bytes and then process them here.

        bool result = false;
        (bool success, uint256 updatedBalance) = ASSETS_CONTRACT.depositTo(srcChainId, token, depositor, amount);
        if (!success) {
            revert DepositRequestShouldNotFail(srcChainId, lzNonce);
        }
        emit DepositResult(true, bytes32(token), bytes32(depositor), amount);

        try DELEGATION_CONTRACT.delegateToThroughClientChain(srcChainId, lzNonce, token, depositor, operator, amount)
        returns (bool delegateSuccess) {
            result = delegateSuccess;
            _sendInterchainMsg(
                srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, delegateSuccess, updatedBalance), true
            );
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, updatedBalance), true);
        }
        emit DelegateResult(result, bytes32(token), bytes32(depositor), string(operator), amount);
    }

    /// @notice Handles the associating operator request, and no response would be returned.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestAssociateOperatorWithStaker(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, ASSOCIATE_OPERATOR_REQUEST_LENGTH, Action.REQUEST_ASSOCIATE_OPERATOR);

        bytes calldata staker = payload[:32];
        bytes calldata operator = payload[32:74];

        bool result = false;
        try DELEGATION_CONTRACT.associateOperatorWithStaker(srcChainId, staker, operator) returns (bool success) {
            result = success;
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
        }

        emit AssociateOperatorResult(result, bytes32(staker), operator);
    }

    /// @notice Handles the dissociating operator request, and no response would be returned.
    /// @dev Can only be called from this contract via low-level call.
    /// @param srcChainId The source chain id.
    /// @param lzNonce The layer zero nonce.
    /// @param payload The request payload.
    function requestDissociateOperatorFromStaker(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, DISSOCIATE_OPERATOR_REQUEST_LENGTH, Action.REQUEST_DISSOCIATE_OPERATOR);

        bytes calldata staker = payload[:32];

        bool result = false;
        try DELEGATION_CONTRACT.dissociateOperatorFromStaker(srcChainId, staker) returns (bool success) {
            result = success;
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
        }

        emit DissociateOperatorResult(result, bytes32(staker));
    }

    /// @dev Validates the payload length, that it matches the expected length.
    /// @param payload The payload to validate.
    /// @param expectedLength The expected length of the payload.
    /// @param action The action that the payload is for.
    function _validatePayloadLength(bytes calldata payload, uint256 expectedLength, Action action) private pure {
        if (payload.length != expectedLength) {
            revert InvalidRequestLength(action, expectedLength, payload.length);
        }
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
