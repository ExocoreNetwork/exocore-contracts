pragma solidity ^0.8.19;

import {ExocoreGatewayStorage} from "../storage/ExocoreGatewayStorage.sol";
import {IExocoreGateway} from "../interfaces/IExocoreGateway.sol";
import {
OAppReceiverUpgradeable,
OAppUpgradeable,
Origin,
MessagingFee,
MessagingReceipt
} from "../lzApp/OAppUpgradeable.sol";

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {ILayerZeroReceiver} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroReceiver.sol";
import {IClientChains} from "../interfaces/precompiles/IClientChains.sol";

contract ExocoreGateway is
Initializable,
PausableUpgradeable,
OwnableUpgradeable,
IExocoreGateway,
ExocoreGatewayStorage,
OAppUpgradeable
{
    using OptionsBuilder for bytes;

    modifier onlyCalledFromThis() {
        require(msg.sender == address(this), "ExocoreGateway: can only be called from this contract itself");
        _;
    }

    constructor(address endpoint_) OAppUpgradeable(endpoint_) {
        _disableInitializers();
    }

    receive() external payable {}

    function initialize(address payable exocoreValidatorSetAddress_) external initializer {
        require(exocoreValidatorSetAddress_ != address(0), "ExocoreGateway: invalid empty exocore validator set address");

        exocoreValidatorSetAddress = exocoreValidatorSetAddress_;

        _initializeWhitelistFunctionSelectors();
        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __OAppCore_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    function _initializeWhitelistFunctionSelectors() private {
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = this.requestDeposit.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.requestDelegateTo.selector;
        _whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.requestUndelegateFrom.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE] = this.requestWithdrawPrinciple.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] = this.requestWithdrawReward.selector;
    }

    function markBootstrapOnAllChains() public {
        (bool success, uint16[] memory clientChainIds) = IClientChains(CLIENT_CHAINS_PRECOMPILE_ADDRESS).getClientChains();
        require(success, "ExocoreGateway: failed to get client chain ids");

        for (uint256 i = 0; i < clientChainIds.length; i++) {
            uint16 clientChainId = clientChainIds[i];
            if (!chainToBootstrapped[clientChainId]) {
                _sendInterchainMsg(uint32(clientChainId), Action.MARK_BOOTSTRAP, "");
                chainToBootstrapped[clientChainId] = true;
            }
        }
    }

    function pause() external {
        require(msg.sender == exocoreValidatorSetAddress, "ExocoreGateway: caller is not Exocore validator set aggregated address");
        _pause();
    }

    function unpause() external {
        require(msg.sender == exocoreValidatorSetAddress, "ExocoreGateway: caller is not Exocore validator set aggregated address");
        _unpause();
    }

    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override whenNotPaused {
        _consumeInboundNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        bytes4 selector_ = _whiteListFunctionSelectors[act];
        if (selector_ == bytes4(0)) {
            revert UnsupportedRequest(act);
        }

        (bool success, bytes memory responseOrReason) = address(this).call(
            abi.encodePacked(selector_, abi.encode(_origin.srcEid, _origin.nonce, payload[1:]))
        );
        if (!success) {
            revert RequestExecuteFailed(act, _origin.nonce, responseOrReason);
        }
    }

    function requestDeposit(uint32 clientChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _handleRequest(clientChainId, lzNonce, payload, DEPOSIT_REQUEST_LENGTH, DEPOSIT_PRECOMPILE_ADDRESS, DEPOSIT_FUNCTION_SELECTOR, Action.REQUEST_DEPOSIT);
    }

    function requestWithdrawPrinciple(uint32 clientChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _handleRequest(clientChainId, lzNonce, payload, WITHDRAW_PRINCIPLE_REQUEST_LENGTH, WITHDRAW_PRINCIPLE_PRECOMPILE_ADDRESS, WITHDRAW_PRINCIPLE_FUNCTION_SELECTOR, Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE);
    }

    function requestWithdrawReward(uint32 clientChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _handleRequest(clientChainId, lzNonce, payload, CLAIM_REWARD_REQUEST_LENGTH, CLAIM_REWARD_PRECOMPILE_ADDRESS, CLAIM_REWARD_FUNCTION_SELECTOR, Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE);
    }

    function requestDelegateTo(uint32 clientChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _handleRequestWithOperator(clientChainId, lzNonce, payload, DELEGATE_REQUEST_LENGTH, DELEGATION_PRECOMPILE_ADDRESS, DELEGATE_TO_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR, Action.REQUEST_DELEGATE_TO);
    }

    function requestUndelegateFrom(uint32 clientChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _handleRequestWithOperator(clientChainId, lzNonce, payload, UNDELEGATE_REQUEST_LENGTH, DELEGATION_PRECOMPILE_ADDRESS, UNDELEGATE_FROM_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR, Action.REQUEST_UNDELEGATE_FROM);
    }

    function _handleRequest(uint32 clientChainId, uint64 lzNonce, bytes calldata payload, uint256 expectedLength, address precompileAddress, bytes4 functionSelector, Action action) private {
        _validatePayloadLength(payload, expectedLength, action);
        _decodeAndCall(precompileAddress, functionSelector, payload, clientChainId, lzNonce, action);
    }

    function _handleRequestWithOperator(uint32 clientChainId, uint64 lzNonce, bytes calldata payload, uint256 expectedLength, address precompileAddress, bytes4 functionSelector, Action action) private {
        _validatePayloadLength(payload, expectedLength, action);
        _decodeAndCallWithOperator(precompileAddress, functionSelector, payload, clientChainId, lzNonce, action);
    }

    function _decodeAndCall(address precompileAddress, bytes4 functionSelector, bytes calldata payload, uint32 clientChainId, uint64 lzNonce, Action action) private {
        bytes calldata token = payload[:32];
        bytes calldata user = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = precompileAddress.call(
            abi.encodeWithSelector(functionSelector, clientChainId, token, user, amount)
        );

        uint256 updatedBalance;
        if (success) {
            (, updatedBalance) = abi.decode(responseOrReason, (bool, uint256));
        }
        _sendInterchainMsg(clientChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance));
    }

    function _decodeAndCallWithOperator(address precompileAddress, bytes4 functionSelector, bytes calldata payload, uint32 clientChainId, uint64 lzNonce, Action action) private {
        bytes calldata token = payload[:32];
        bytes calldata user = payload[32:64];
        bytes calldata operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        (bool success,) = precompileAddress.call(
            abi.encodeWithSelector(functionSelector, clientChainId, lzNonce, token, user, operator, amount)
        );
        _sendInterchainMsg(clientChainId, Action.RESPOND, abi.encodePacked(lzNonce, success));
    }

    function _validatePayloadLength(bytes calldata payload, uint256 expectedLength, Action action) private pure {
        if (payload.length != expectedLength) {
            revert InvalidRequestLength(action, expectedLength, payload.length);
        }
    }

    function _sendInterchainMsg(uint32 clientChainId, Action act, bytes memory actionArgs) internal whenNotPaused {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE)
            .addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(clientChainId, payload, options, false);

        MessagingReceipt memory receipt = _lzSend(clientChainId, payload, options, MessagingFee(fee.nativeFee, 0), exocoreValidatorSetAddress, true);
        emit MessageSent(act, receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }

    function quote(uint32 clientChainId, bytes memory _message) public view returns (uint256 nativeFee) {
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE)
            .addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(clientChainId, _message, options, false);
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

    function _consumeInboundNonce(uint32 srcEid, bytes32 sender, uint64 nonce) internal {
        inboundNonce[srcEid][sender] += 1;
        if (nonce != inboundNonce[srcEid][sender]) {
            revert UnexpectedInboundNonce(inboundNonce[srcEid][sender], nonce);
        }
    }
}
