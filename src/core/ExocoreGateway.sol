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

import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {ILayerZeroReceiver} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroReceiver.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

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

    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "ExocoreGateway: can only be called from this contract itself with a low-level call"
        );
        _;
    }

    constructor(address endpoint_) OAppUpgradeable(endpoint_) {
        _disableInitializers();
    }

    receive() external payable {}

    function initialize(address payable exocoreValidatorSetAddress_) external initializer {
        require(
            exocoreValidatorSetAddress_ != address(0),
            "ExocoreGateway: validator set address cannot be the zero address"
        );

        exocoreValidatorSetAddress = exocoreValidatorSetAddress_;

        _initializeWhitelistFunctionSelectors();
        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __OAppCore_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
        __ReentrancyGuard_init_unchained();
    }

    function _initializeWhitelistFunctionSelectors() private {
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = this.requestDeposit.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.requestDelegateTo.selector;
        _whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.requestUndelegateFrom.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE] =
            this.requestWithdrawPrincipal.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] = this.requestWithdrawReward.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO] =
            this.requestDepositThenDelegateTo.selector;
        _whiteListFunctionSelectors[Action.REQUEST_REGISTER_TOKENS] = this.requestRegisterTokens.selector;
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
                _sendInterchainMsg(clientChainId, Action.REQUEST_MARK_BOOTSTRAP, "");
                // TODO: should this be marked only upon receiving a response?
                chainToBootstrapped[clientChainId] = true;
            }
        }
    }

    /**
     * @notice Sets the peer address (OApp instance) for a corresponding endpoint. This would also
     * register the `cientChainId` to Exocore native module if the peer address is first time being set.
     * @param clientChainId The endpoint ID for client chain.
     * @param clientChainGateway The contract address to be associated with the corresponding endpoint.
     * @param addressLength The bytes length of address type on that client chain
     * @param name The name of client chain
     * @param metaInfo The arbitrary metadata for client chain
     * @param signatureType The cryptographic signature type that client chain supports
     *
     * @dev Only the owner/admin of the OApp can call this function.
     * @dev Indicates that the peer is trusted to send LayerZero messages to this OApp.
     * @dev Peer is a bytes32 to accommodate non-evm chains.
     */
    function setPeer(
        uint32 clientChainId, 
        bytes32 clientChainGateway,
        uint32 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    )
        public
        override(IOAppCore, OAppCoreUpgradeable)
        onlyOwner
        whenNotPaused
    {
        _validatePeer(clientChainId, clientChainGateway);
        _registerClientChain(
            clientChainId,
            addressLength,
            name,
            metaInfo,
            signatureType
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
    ) external payable onlyOwner whenNotPaused {
        _validateWhitelistTokensInput(
            clientChainId,
            tokens,
            decimals,
            tvlLimits,
            names,
            metadata
        );

        bool success = ASSETS_CONTRACT.registerTokens(
            srcChainId, 
            tokens, 
            decimals, 
            tvlLimits,
            string[] memory names,
            string[] memory metaData
        );

        if (!success) {
            revert AddWhitelistTokensFailed();
        }

        _sendInterchainMsg(clientChainId, Action.REQUEST_ADD_WHITELIST_TOKENS, abi.encodePacked(uint8(tokens.length), tokens));
    }

    function _validateWhitelistTokensInput(
        uint32 clientChainId,
        bytes32[] calldata tokens,
        uint8[] calldata decimals,
        uint256[] calldata tvlLimits,
        string[] calldata names,
        string[] calldata metaData
    ) internal pure {
        if (peers[clientChainId] != bytes32(0)) {
            revert ClientChainIDNotRegisteredBefore(clientChainId);
        }

        uint256 expectedLength = tokens.length;
        if (expectedLength > type(uint8).max) {
            revert WhitelistTokensListTooLong();
        }

        if (
            decimals.length != expectedLength ||
            tvlLimits.length != expectedLength ||
            names.length != expectedLength ||
            metaData.length != expectedLength 
        ) {
            revert InvalidWhitelistTokensInput();
        }
    }

    function _validatePeer(uint32 clientChainId, bytes32 clientChainGateway) internal pure {
        require(clientChainId != uint32(0), "ExocoreGateway: zero value is not invalid endpoint id");
        require(clientChainGateway != bytes32(0), "ExocoreGateway: client chain gateway cannot be empty");
    }

    function _registerClientChain(
        uint32 clientChainID,
        uint32 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) internal {
        if (peers[clientChainId] == bytes32(0)) {
            bool success = ASSETS_CONTRACT.registerClientChain(
                clientChainID,
                addressLength,
                name,
                metaInfo,
                signatureType
            );
            if (!success) {
                revert RegisterClientChainToExocoreFailed(clientChainId);
            }
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

        bytes32 token = bytes32(payload[:32]);
        bytes32 depositor = bytes32(payload[32:64]);
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, uint256 updatedBalance) = ASSETS_CONTRACT.depositTo(srcChainId, token, depositor, amount);
        if (!success) {
            revert DepositRequestShouldNotFail(srcChainId, lzNonce);
        }

        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance));
    }

    function requestWithdrawPrincipal(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(
            payload, WITHDRAW_PRINCIPAL_REQUEST_LENGTH, Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE
        );

        bytes32 token = bytes32(payload[:32]);
        bytes32 withdrawer = bytes32(payload[32:64]);
        uint256 amount = uint256(bytes32(payload[64:96]));

        try ASSETS_CONTRACT.withdrawPrincipal(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance));
        } catch {
            emit ExocorePrecompileError(ASSETS_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)));
        }
    }

    function requestWithdrawReward(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, CLAIM_REWARD_REQUEST_LENGTH, Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE);

        bytes32 token = bytes32(payload[:32]);
        bytes32 withdrawer = bytes32(payload[32:64]);
        uint256 amount = uint256(bytes32(payload[64:96]));

        try CLAIM_REWARD_CONTRACT.claimReward(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance));
        } catch {
            emit ExocorePrecompileError(CLAIM_REWARD_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)));
        }
    }

    function requestDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _validatePayloadLength(payload, DELEGATE_REQUEST_LENGTH, Action.REQUEST_DELEGATE_TO);

        bytes32 token = bytes32(payload[:32]);
        bytes32 delegator = bytes32(payload[32:64]);
        bytes32 operator = bytes32(payload[64:106]);
        uint256 amount = uint256(bytes32(payload[106:138]));

        try DELEGATION_CONTRACT.delegateToThroughClientChain(srcChainId, lzNonce, token, delegator, operator, amount)
        returns (bool success) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success));
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false));
        }
    }

    function requestUndelegateFrom(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, UNDELEGATE_REQUEST_LENGTH, Action.REQUEST_UNDELEGATE_FROM);

        bytes32 token = bytes32(payload[:32]);
        bytes32 delegator = bytes32(payload[32:64]);
        bytes32 operator = bytes32(payload[64:106]);
        uint256 amount = uint256(bytes32(payload[106:138]));

        try DELEGATION_CONTRACT.undelegateFromThroughClientChain(
            srcChainId, lzNonce, token, delegator, operator, amount
        ) returns (bool success) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success));
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false));
        }
    }

    function requestDepositThenDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH, Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO);

        bytes32 token = bytes32(payload[:32]);
        bytes32 depositor = bytes32(payload[32:64]);
        bytes32 operator = bytes32(payload[64:106]);
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
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, delegateSuccess, updatedBalance));
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, updatedBalance));
        }
    }

    function _validatePayloadLength(bytes calldata payload, uint256 expectedLength, Action action) private pure {
        if (payload.length != expectedLength) {
            revert InvalidRequestLength(action, expectedLength, payload.length);
        }
    }

    function _sendInterchainMsg(uint32 srcChainId, Action act, bytes memory actionArgs) internal whenNotPaused {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(srcChainId, payload, options, false);

        MessagingReceipt memory receipt =
            _lzSend(srcChainId, payload, options, MessagingFee(fee.nativeFee, 0), exocoreValidatorSetAddress, true);
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
