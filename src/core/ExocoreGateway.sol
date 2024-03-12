pragma solidity ^0.8.19;

import {ExocoreGatewayStorage} from "../storage/ExocoreGatewayStorage.sol";
import {ECDSA} from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OAppUpgradeable, Origin, MessagingFee, MessagingReceipt} from "../lzApp/OAppUpgradeable.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";

contract ExocoreGateway is
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ExocoreGatewayStorage,
    OAppUpgradeable
{
    using OptionsBuilder for bytes;

    modifier onlyCalledFromThis() {
        require(msg.sender == address(this), "could only be called from this contract itself with low level call");
        _;
    }

    constructor(address _endpoint) OAppUpgradeable(_endpoint) {
        _disableInitializers();
    }

    receive() external payable {}

    function initialize(address payable _exocoreValidatorSetAddress) external initializer {
        require(_exocoreValidatorSetAddress != address(0), "invalid empty exocore validator set address");

        exocoreValidatorSetAddress = _exocoreValidatorSetAddress;

        whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = this.requestDeposit.selector;
        whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.requestDelegateTo.selector;
        whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.requestUndelegateFrom.selector;
        whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE] =
            this.requestWithdrawPrinciple.selector;
        whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] = this.requestWithdrawReward.selector;

        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __OAppCore_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    function pause() external {
        require(
            msg.sender == exocoreValidatorSetAddress, "only Exocore validator set aggregated address could call this"
        );
        _pause();
    }

    function unpause() external {
        require(
            msg.sender == exocoreValidatorSetAddress, "only Exocore validator set aggregated address could call this"
        );
        _unpause();
    }

    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override whenNotPaused {
        // TODO: current exocore precompiles take srcChainId as uint16, so this check should be removed after exocore network fixes it
        require(_origin.srcEid <= type(uint16).max, "source chain endpoint id should not exceed uint16.max");

        _consumeInboundNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        bytes4 selector_ = whiteListFunctionSelectors[act];
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
        bytes calldata token = payload[:32];
        bytes calldata depositor = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = DEPOSIT_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                DEPOSIT_FUNCTION_SELECTOR,
                uint16(srcChainId), // TODO: Casting srcChainId from uint32 to uint16 should be fixed after exocore network fix source chain id type
                token,
                depositor,
                amount
            )
        );

        uint256 lastlyUpdatedPrincipleBalance;
        if (success) {
            (, lastlyUpdatedPrincipleBalance) = abi.decode(responseOrReason, (bool, uint256));
        }
        _sendInterchainMsg(
            srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, lastlyUpdatedPrincipleBalance)
        );
    }

    function requestWithdrawPrinciple(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bytes calldata token = payload[:32];
        bytes calldata withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = WITHDRAW_PRINCIPLE_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                WITHDRAW_PRINCIPLE_FUNCTION_SELECTOR,
                uint16(srcChainId), // TODO: Casting srcChainId from uint32 to uint16 should be fixed after exocore network fix source chain id type
                token,
                withdrawer,
                amount
            )
        );

        uint256 lastlyUpdatedPrincipleBalance;
        if (success) {
            (, lastlyUpdatedPrincipleBalance) = abi.decode(responseOrReason, (bool, uint256));
        }
        _sendInterchainMsg(
            srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, lastlyUpdatedPrincipleBalance)
        );
    }

    function requestWithdrawReward(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bytes calldata token = payload[:32];
        bytes calldata withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = CLAIM_REWARD_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                CLAIM_REWARD_FUNCTION_SELECTOR,
                uint16(srcChainId), // TODO: Casting srcChainId from uint32 to uint16 should be fixed after exocore network fix source chain id type
                token,
                withdrawer,
                amount
            )
        );

        uint256 lastlyUpdatedRewardBalance;
        if (success) {
            (, lastlyUpdatedRewardBalance) = abi.decode(responseOrReason, (bool, uint256));
        }
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, lastlyUpdatedRewardBalance));
    }

    function requestDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        bytes calldata token = payload[:32];
        bytes calldata delegator = payload[32:64];
        bytes calldata operator = payload[64:108];
        uint256 amount = uint256(bytes32(payload[108:140]));

        (bool success,) = DELEGATION_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                DELEGATE_TO_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR,
                uint16(srcChainId), // TODO: Casting srcChainId from uint32 to uint16 should be fixed after exocore network fix source chain id type
                lzNonce,
                token,
                delegator,
                operator,
                amount
            )
        );
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success));
    }

    function requestUndelegateFrom(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        bytes memory token = payload[1:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:108];
        uint256 amount = uint256(bytes32(payload[108:140]));

        (bool success,) = DELEGATION_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                UNDELEGATE_FROM_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR,
                uint16(srcChainId), // TODO: Casting srcChainId from uint32 to uint16 should be fixed after exocore network fix source chain id type
                lzNonce,
                token,
                delegator,
                operator,
                amount
            )
        );
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success));
    }

    function _sendInterchainMsg(uint32 srcChainId, Action act, bytes memory actionArgs) internal whenNotPaused {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        bytes memory options =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE);
        MessagingFee memory fee = _quote(srcChainId, payload, options, false);

        MessagingReceipt memory receipt =
            _lzSend(srcChainId, payload, options, MessagingFee(fee.nativeFee, 0), exocoreValidatorSetAddress, true);
        emit MessageSent(act, receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }

    function quote(uint32 srcChainid, bytes memory _message) public view returns (uint256 nativeFee) {
        bytes memory options =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE);
        MessagingFee memory fee = _quote(srcChainid, _message, options, false);
        return fee.nativeFee;
    }

    function getInboundNonce(uint32 srcEid, bytes32 sender) public view returns (uint64) {
        return inboundNonce[srcEid][sender];
    }

    function _consumeInboundNonce(uint32 srcEid, bytes32 sender, uint64 nonce) internal {
        inboundNonce[srcEid][sender] += 1;
        if (nonce != inboundNonce[srcEid][sender]) {
            revert UnexpectedInboundNonce(inboundNonce[srcEid][sender], nonce);
        }
    }
}
