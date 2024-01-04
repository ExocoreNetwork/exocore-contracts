pragma solidity ^0.8.19;

import {ExocoreGatewayStorage} from "../storage/ExocoreGatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {LzAppUpgradeable} from "../lzApp/LzAppUpgradeable.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/security/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";

contract ExocoreGateway is 
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable, 
    ExocoreGatewayStorage,
    LzAppUpgradeable
{
    
    event InterchainMsgReceived(
        uint16 indexed srcChainID,
        bytes indexed srcChainAddress,
        uint64 indexed nonce,
        bytes payload
    );
    error UnsupportedRequest(Action act); 
    error RequestExecuteFailed(Action act, uint64 nonce, bytes reason);
    error PrecompileCallFailed(bytes4 selector_, bytes reason);

    modifier onlyCalledFromThis() {
        require(msg.sender == address(this), "could only be called from this contract itself with low level call");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    receive() external payable {}

    function initialize(address payable _ExocoreValidatorSetAddress, address _lzEndpoint) external initializer {
        require(_ExocoreValidatorSetAddress != address(0), "invalid empty exocore validator set address");
        require(_lzEndpoint != address(0), "invalid layerzero endpoint address");
        ExocoreValidatorSetAddress = _ExocoreValidatorSetAddress;
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);

        whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = this.requestDeposit.selector;
        whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.requestDelegateTo.selector;
        whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.requestUndelegateFrom.selector;
        whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE] = this.requestWithdrawPrinciple.selector;
        whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] = this.requestWithdrawReward.selector;

        _transferOwnership(ExocoreValidatorSetAddress);
        __Pausable_init();
    }

    function pause() external {
        require(msg.sender == ExocoreValidatorSetAddress, "only Exocore validator set aggregated address could call this");
        _pause();
    }

    function unpause() external {
        require(msg.sender == ExocoreValidatorSetAddress, "only Exocore validator set aggregated address could call this");
        _unpause();
    }

    function _blockingLzReceive(uint16 srcChainId, bytes memory srcAddress, uint64 nonce, bytes calldata payload) 
        internal 
        virtual 
        override
        whenNotPaused 
    {
        address fromAddress;
        assembly {
            fromAddress := mload(add(srcAddress, 20))
        }

        Action act = Action(uint8(payload[0]));
        bytes4 selector_ = whiteListFunctionSelectors[act];
        if (selector_ == bytes4(0)) {
            revert UnsupportedRequest(act);
        }

        (bool success, bytes memory responseOrReason) = address(this).call(abi.encodePacked(selector_, abi.encode(srcChainId, nonce, payload[1:])));
        if (!success) {
            revert RequestExecuteFailed(act, nonce, responseOrReason);
        }
    }

    function requestDeposit(uint16 srcChainId, uint64 lzNonce, bytes calldata payload) 
        public 
        onlyCalledFromThis 
    {
        bytes calldata token = payload[:32];
        bytes calldata depositor = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = DEPOSIT_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                DEPOSIT_FUNCTION_SELECTOR, 
                srcChainId, 
                token, 
                depositor, 
                amount
            )
        );

        uint256 lastlyUpdatedPrincipleBalance;
        if (success) {
            (, lastlyUpdatedPrincipleBalance) = abi.decode(responseOrReason, (bool, uint256));
        }
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, lastlyUpdatedPrincipleBalance));
    }

    function requestWithdrawPrinciple(uint16 srcChainId, uint64 lzNonce, bytes calldata payload) 
        public 
        onlyCalledFromThis 
    {
        bytes calldata token = payload[:32];
        bytes calldata withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = WITHDRAW_PRINCIPLE_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                WITHDRAW_PRINCIPLE_FUNCTION_SELECTOR, 
                srcChainId, 
                token, 
                withdrawer, 
                amount
            )
        );

        uint256 lastlyUpdatedPrincipleBalance;
        if (success) {
            (, lastlyUpdatedPrincipleBalance) = abi.decode(responseOrReason, (bool, uint256));
        }
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, lastlyUpdatedPrincipleBalance));
    }

    function requestWithdrawReward(uint16 srcChainId, uint64 lzNonce, bytes calldata payload) 
        public 
        onlyCalledFromThis 
    {
        bytes calldata token = payload[:32];
        bytes calldata withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = CLAIM_REWARD_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                CLAIM_REWARD_FUNCTION_SELECTOR, 
                srcChainId, 
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

    function requestDelegateTo(uint16 srcChainId, uint64 lzNonce, bytes calldata payload) 
        public 
        onlyCalledFromThis 
    {
        bytes calldata token = payload[:32];
        bytes calldata delegator = payload[32:64];
        bytes calldata operator = payload[64:108];
        uint256 amount = uint256(bytes32(payload[108:140]));

        (bool success, ) = DELEGATION_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                DELEGATE_TO_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR, 
                srcChainId,
                lzNonce, 
                token, 
                delegator,
                operator, 
                amount
            )
        );
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success));
    }

    function requestUndelegateFrom(uint16 srcChainId, uint64 lzNonce, bytes calldata payload) 
        public 
        onlyCalledFromThis
    {
        bytes memory token = payload[1:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:108];
        uint256 amount = uint256(bytes32(payload[108:140]));

        (bool success, ) = DELEGATION_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                UNDELEGATE_FROM_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR, 
                srcChainId,
                lzNonce, 
                token, 
                delegator,
                operator, 
                amount
            )
        );
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success));
    }

    function _sendInterchainMsg(uint16 srcChainId, Action act, bytes memory actionArgs) internal whenNotPaused {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        (uint256 lzFee, ) = lzEndpoint.estimateFees(srcChainId, address(this), payload, false, "");
        _lzSend(srcChainId, payload, payable(address(this)), address(0), "", lzFee);
    }
}