pragma solidity ^0.8.19;

import {IExocoreGateway} from "src/interfaces/IExocoreGateway.sol";

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

    function initialize(address payable exocoreValidatorSetAddress_) external initializer {
        require(exocoreValidatorSetAddress_ != address(0), "ExocoreGateway: invalid exocore validator set address");

        exocoreValidatorSetAddress = exocoreValidatorSetAddress_;

        _initializeWhitelistFunctionSelectors();
        _transferOwnership(exocoreValidatorSetAddress);
        __OAppCore_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    function _initializeWhitelistFunctionSelectors() private {
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = this.requestDeposit.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.requestDelegateTo.selector;
        _whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.requestUndelegateFrom.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE] =
            this.requestWithdrawPrincipal.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] = this.requestWithdrawReward.selector;
    }

    function pause() external {
        require(
            msg.sender == exocoreValidatorSetAddress,
            "ExocoreGateway: caller is not Exocore validator set aggregated address"
        );
        _pause();
    }

    function unpause() external {
        require(
            msg.sender == exocoreValidatorSetAddress,
            "ExocoreGateway: caller is not Exocore validator set aggregated address"
        );
        _unpause();
    }

    // TODO: call this function automatically, either within the initializer (which requires
    // setPeer) or be triggered by Golang after the contract is deployed.
    // For manual calls, this function should be called immediately after deployment and
    // then never needs to be called again.
    function markBootstrapOnAllChains() public whenNotPaused nonReentrant {
        (bool success, bytes memory result) =
            ASSETS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(ASSETS_CONTRACT.getClientChains.selector));
        require(success, "ExocoreGateway: failed to get client chain ids");
        (bool ok, uint32[] memory clientChainIds) = abi.decode(result, (bool, uint32[]));
        require(ok, "ExocoreGateway: failed to decode client chain ids");
        for (uint256 i = 0; i < clientChainIds.length; i++) {
            uint32 clientChainId = clientChainIds[i];
            if (!chainToBootstrapped[clientChainId]) {
                _sendInterchainMsg(clientChainId, Action.REQUEST_MARK_BOOTSTRAP, "", true);
                // TODO: should this be marked only upon receiving a response?
                chainToBootstrapped[clientChainId] = true;
            }
        }
    }

    /**
     * @notice Register the `cientChainId` and othe meta data to Exocore native module or update clien chain's meta data
     * according to the `clinetChainId`.
     * And set trusted remote peer to enable layerzero messaging or other bridge messaging.
     * @param clientChainId The endpoint ID for client chain.
     * @param peer The trusted remote contract address to be associated with the corresponding endpoint or some
     * authorized signer that would be trusted for
     * sending messages from/to source chain to/from this contract
     * @param addressLength The bytes length of address type on that client chain
     * @param name The name of client chain
     * @param metaInfo The arbitrary metadata for client chain
     * @param signatureType The cryptographic signature type that client chain supports
     *
     * @dev Only the owner/admin of the OApp can call this function.
     * @dev Indicates that the peer is trusted to send LayerZero messages to this OApp.
     * @dev Peer is a bytes32 to accommodate non-evm chains.
     */
    function registerOrUpdateClientChain(
        uint32 clientChainId,
        bytes32 peer,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) public onlyOwner whenNotPaused {
        require(clientChainId != uint32(0), "ExocoreGateway: client chain id cannot be zero or empty");
        require(peer != bytes32(0), "ExocoreGateway: peer address cannot be zero or empty");
        require(addressLength != 0, "ExocoreGateway: address length cannot be zero or empty");
        require(bytes(name).length != 0, "ExocoreGateway: name cannot be empty");
        require(bytes(metaInfo).length != 0, "ExocoreGateway: meta data cannot be empty");
        // signature type could be left as empty for current implementation

        _registerClientChain(clientChainId, addressLength, name, metaInfo, signatureType);
        super.setPeer(clientChainId, peer);

        if (!isRegisteredClientChain[clientChainId]) {
            isRegisteredClientChain[clientChainId] = true;
            emit ClientChainRegistered(clientChainId);
        } else {
            emit ClientChainUpdated(clientChainId);
        }
    }

    function setPeer(uint32 clientChainId, bytes32 clientChainGateway)
        public
        override(IOAppCore, OAppCoreUpgradeable)
        onlyOwner
        whenNotPaused
    {
        require(
            isRegisteredClientChain[clientChainId],
            "ExocoreGateway: client chain should be registered before setting peer to change peer address"
        );

        super.setPeer(clientChainId, clientChainGateway);
    }

    function addWhitelistTokens(
        uint32 clientChainId,
        bytes32[] calldata tokens,
        uint8[] calldata decimals,
        uint256[] calldata tvlLimits,
        string[] calldata names,
        string[] calldata metaData
    ) external payable onlyOwner whenNotPaused nonReentrant {
        _validateWhitelistTokensInput(clientChainId, tokens, decimals, tvlLimits, names, metaData);

        for (uint256 i; i < tokens.length; i++) {
            require(tokens[i] != bytes32(0), "ExocoreGateway: token cannot be zero address");
            require(!isWhitelistedToken[tokens[i]], "ExocoreGateway: token has already been added to whitelist before");
            require(tvlLimits[i] > 0, "ExocoreGateway: tvl limit should not be zero");
            require(bytes(names[i]).length != 0, "ExocoreGateway: name cannot be empty");
            require(bytes(metaData[i]).length != 0, "ExocoreGateway: meta data cannot be empty");

            bool success = ASSETS_CONTRACT.registerToken(
                clientChainId, abi.encodePacked(tokens[i]), decimals[i], tvlLimits[i], names[i], metaData[i]
            );

            if (success) {
                isWhitelistedToken[tokens[i]] = true;
            } else {
                revert AddWhitelistTokenFailed(tokens[i]);
            }

            emit WhitelistTokenAdded(clientChainId, tokens[i]);
        }

        _sendInterchainMsg(
            clientChainId, Action.REQUEST_ADD_WHITELIST_TOKENS, abi.encodePacked(uint8(tokens.length), tokens), false
        );
    }

    function updateWhitelistedTokens(
        uint32 clientChainId,
        bytes32[] calldata tokens,
        uint8[] calldata decimals,
        uint256[] calldata tvlLimits,
        string[] calldata names,
        string[] calldata metaData
    ) external onlyOwner whenNotPaused {
        _validateWhitelistTokensInput(clientChainId, tokens, decimals, tvlLimits, names, metaData);

        for (uint256 i; i < tokens.length; i++) {
            require(tokens[i] != bytes32(0), "ExocoreGateway: token cannot be zero address");
            require(isWhitelistedToken[tokens[i]], "ExocoreGateway: token has not been added to whitelist before");
            require(tvlLimits[i] > 0, "ExocoreGateway: tvl limit should not be zero");
            require(bytes(names[i]).length != 0, "ExocoreGateway: name cannot be empty");
            require(bytes(metaData[i]).length != 0, "ExocoreGateway: meta data cannot be empty");

            bool success = ASSETS_CONTRACT.registerToken(
                clientChainId, abi.encodePacked(tokens[i]), decimals[i], tvlLimits[i], names[i], metaData[i]
            );

            if (!success) {
                revert UpdateWhitelistTokenFailed(tokens[i]);
            }

            emit WhitelistTokenUpdated(clientChainId, tokens[i]);
        }
    }

    function _validateWhitelistTokensInput(
        uint32 clientChainId,
        bytes32[] calldata tokens,
        uint8[] calldata decimals,
        uint256[] calldata tvlLimits,
        string[] calldata names,
        string[] calldata metaData
    ) internal view {
        if (!isRegisteredClientChain[clientChainId]) {
            revert ClientChainIDNotRegisteredBefore(clientChainId);
        }

        uint256 expectedLength = tokens.length;
        if (expectedLength > type(uint8).max) {
            revert WhitelistTokensListTooLong();
        }

        if (
            decimals.length != expectedLength || tvlLimits.length != expectedLength || names.length != expectedLength
                || metaData.length != expectedLength
        ) {
            revert InvalidWhitelistTokensInput();
        }
    }

    function _registerClientChain(
        uint32 clientChainId,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) internal {
        bool success = ASSETS_CONTRACT.registerClientChain(clientChainId, addressLength, name, metaInfo, signatureType);
        if (!success) {
            revert RegisterClientChainToExocoreFailed(clientChainId);
        }
    }

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
    }

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

        try ASSETS_CONTRACT.withdrawPrincipal(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);
        } catch {
            emit ExocorePrecompileError(ASSETS_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)), true);
        }
    }

    function requestWithdrawReward(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, CLAIM_REWARD_REQUEST_LENGTH, Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE);

        bytes memory token = payload[:32];
        bytes memory withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        try CLAIM_REWARD_CONTRACT.claimReward(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);
        } catch {
            emit ExocorePrecompileError(CLAIM_REWARD_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)), true);
        }
    }

    function requestDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _validatePayloadLength(payload, DELEGATE_REQUEST_LENGTH, Action.REQUEST_DELEGATE_TO);

        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        try DELEGATION_CONTRACT.delegateToThroughClientChain(srcChainId, lzNonce, token, delegator, operator, amount)
        returns (bool success) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success), true);
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false), true);
        }
    }

    function requestUndelegateFrom(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, UNDELEGATE_REQUEST_LENGTH, Action.REQUEST_UNDELEGATE_FROM);

        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        try DELEGATION_CONTRACT.undelegateFromThroughClientChain(
            srcChainId, lzNonce, token, delegator, operator, amount
        ) returns (bool success) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success), true);
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false), true);
        }
    }

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

        (bool success, uint256 updatedBalance) = ASSETS_CONTRACT.depositTo(srcChainId, token, depositor, amount);
        if (!success) {
            revert DepositRequestShouldNotFail(srcChainId, lzNonce);
        }
        try DELEGATION_CONTRACT.delegateToThroughClientChain(srcChainId, lzNonce, token, depositor, operator, amount)
        returns (bool delegateSuccess) {
            _sendInterchainMsg(
                srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, delegateSuccess, updatedBalance), true
            );
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, updatedBalance), true);
        }
    }

    function _validatePayloadLength(bytes calldata payload, uint256 expectedLength, Action action) private pure {
        if (payload.length != expectedLength) {
            revert InvalidRequestLength(action, expectedLength, payload.length);
        }
    }

    function _sendInterchainMsg(uint32 srcChainId, Action act, bytes memory actionArgs, bool payByApp)
        internal
        whenNotPaused
    {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(srcChainId, payload, options, false);

        MessagingReceipt memory receipt =
            _lzSend(srcChainId, payload, options, MessagingFee(fee.nativeFee, 0), exocoreValidatorSetAddress, payByApp);
        emit MessageSent(act, receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }

    function quote(uint32 srcChainid, bytes memory _message) public view returns (uint256 nativeFee) {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(srcChainid, _message, options, false);
        return fee.nativeFee;
    }

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
