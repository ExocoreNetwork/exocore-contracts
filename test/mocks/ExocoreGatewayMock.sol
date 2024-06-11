pragma solidity ^0.8.19;

import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";

import {ILayerZeroReceiver} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroReceiver.sol";
import {ECDSA} from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

import {IExocoreGateway} from "src/interfaces/IExocoreGateway.sol";
import {IClientChains} from "src/interfaces/precompiles/IClientChains.sol";
import {
    MessagingFee,
    MessagingReceipt,
    OAppReceiverUpgradeable,
    OAppUpgradeable,
    Origin
} from "src/lzApp/OAppUpgradeable.sol";

contract ExocoreGatewayMock is
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    IExocoreGateway,
    OAppUpgradeable
{

    using OptionsBuilder for bytes;

    enum Action {
        REQUEST_DEPOSIT,
        REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
        REQUEST_WITHDRAW_REWARD_FROM_EXOCORE,
        REQUEST_DELEGATE_TO,
        REQUEST_UNDELEGATE_FROM,
        REQUEST_DEPOSIT_THEN_DELEGATE_TO,
        REQUEST_MARK_BOOTSTRAP,
        RESPOND,
        UPDATE_USERS_BALANCES
    }

    mapping(Action => bytes4) public whiteListFunctionSelectors;
    address payable public exocoreValidatorSetAddress;

    address immutable DEPOSIT_PRECOMPILE_MOCK_ADDRESS;
    address immutable DELEGATION_PRECOMPILE_MOCK_ADDRESS;
    address immutable WITHDRAW_PRINCIPLE_PRECOMPILE_MOCK_ADDRESS;
    address immutable CLAIM_REWARD_PRECOMPILE_MOCK_ADDRESS;
    address immutable CLIENT_CHAINS_PRECOMPILE_MOCK_ADDRESS;

    bytes4 constant DEPOSIT_FUNCTION_SELECTOR = bytes4(keccak256("depositTo(uint32,bytes,bytes,uint256)"));
    bytes4 constant DELEGATE_TO_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR =
        bytes4(keccak256("delegateToThroughClientChain(uint32,uint64,bytes,bytes,bytes,uint256)"));
    bytes4 constant UNDELEGATE_FROM_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR =
        bytes4(keccak256("undelegateFromThroughClientChain(uint32,uint64,bytes,bytes,bytes,uint256)"));
    bytes4 constant WITHDRAW_PRINCIPLE_FUNCTION_SELECTOR =
        bytes4(keccak256("withdrawPrinciple(uint32,bytes,bytes,uint256)"));
    bytes4 constant CLAIM_REWARD_FUNCTION_SELECTOR = bytes4(keccak256("claimReward(uint32,bytes,bytes,uint256)"));

    uint256 constant DEPOSIT_REQUEST_LENGTH = 96;
    uint256 constant DELEGATE_REQUEST_LENGTH = 138;
    uint256 constant UNDELEGATE_REQUEST_LENGTH = 138;
    uint256 constant WITHDRAW_PRINCIPLE_REQUEST_LENGTH = 96;
    uint256 constant CLAIM_REWARD_REQUEST_LENGTH = 96;

    uint128 constant DESTINATION_GAS_LIMIT = 500_000;
    uint128 constant DESTINATION_MSG_VALUE = 0;

    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) inboundNonce;
    mapping(uint16 id => bool) chainToBootstrapped;

    event MessageSent(Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    error UnsupportedRequest(Action act);
    error RequestExecuteFailed(Action act, uint64 nonce, bytes reason);
    error PrecompileCallFailed(bytes4 selector_, bytes reason);
    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);
    error UnexpectedSourceChain(uint32 unexpectedSrcEndpointId);
    error InvalidRequestLength(Action act, uint256 expectedLength, uint256 actualLength);

    uint256[40] private __gap;

    modifier onlyCalledFromThis() {
        require(msg.sender == address(this), "could only be called from this contract itself with low level call");
        _;
    }

    constructor(
        address _endpoint,
        address depositPrecompileMockAddress,
        address withdrawPrinciplePrecompileMockAddress,
        address delegationPrecompileMockAddress,
        address ClaimRewardPrecompileMockAddress
    ) OAppUpgradeable(_endpoint) {
        DEPOSIT_PRECOMPILE_MOCK_ADDRESS = depositPrecompileMockAddress;
        DELEGATION_PRECOMPILE_MOCK_ADDRESS = delegationPrecompileMockAddress;
        WITHDRAW_PRINCIPLE_PRECOMPILE_MOCK_ADDRESS = withdrawPrinciplePrecompileMockAddress;
        CLAIM_REWARD_PRECOMPILE_MOCK_ADDRESS = ClaimRewardPrecompileMockAddress;
        CLIENT_CHAINS_PRECOMPILE_MOCK_ADDRESS = address(0);

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

    // TODO: call this function automatically, either within the initializer (which requires
    // setPeer) or be triggered by Golang after the contract is deployed.
    // For manual calls, this function should be called immediately after deployment and
    // then never needs to be called again.
    function markBootstrapOnAllChains() public {
        (bool success, uint16[] memory clientChainIds) =
            IClientChains(CLIENT_CHAINS_PRECOMPILE_MOCK_ADDRESS).getClientChains();
        require(success, "ExocoreGateway: failed to get client chain ids");

        for (uint256 i = 0; i < clientChainIds.length; i++) {
            uint16 clientChainId = clientChainIds[i];
            if (!chainToBootstrapped[clientChainId]) {
                _sendInterchainMsg(uint32(clientChainId), Action.REQUEST_MARK_BOOTSTRAP, "");
                // TODO: should this be marked only when receiving a response?
                chainToBootstrapped[clientChainId] = true;
            }
        }
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

    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override whenNotPaused {
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
        if (payload.length != DEPOSIT_REQUEST_LENGTH) {
            revert InvalidRequestLength(Action.REQUEST_DEPOSIT, DEPOSIT_REQUEST_LENGTH, payload.length);
        }

        bytes calldata token = payload[:32];
        bytes calldata depositor = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = DEPOSIT_PRECOMPILE_MOCK_ADDRESS.call(
            abi.encodeWithSelector(DEPOSIT_FUNCTION_SELECTOR, srcChainId, token, depositor, amount)
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
        if (payload.length != WITHDRAW_PRINCIPLE_REQUEST_LENGTH) {
            revert InvalidRequestLength(
                Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE, WITHDRAW_PRINCIPLE_REQUEST_LENGTH, payload.length
            );
        }

        bytes calldata token = payload[:32];
        bytes calldata withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = WITHDRAW_PRINCIPLE_PRECOMPILE_MOCK_ADDRESS.call(
            abi.encodeWithSelector(WITHDRAW_PRINCIPLE_FUNCTION_SELECTOR, srcChainId, token, withdrawer, amount)
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
        if (payload.length != CLAIM_REWARD_REQUEST_LENGTH) {
            revert InvalidRequestLength(
                Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE, CLAIM_REWARD_REQUEST_LENGTH, payload.length
            );
        }

        bytes calldata token = payload[:32];
        bytes calldata withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, bytes memory responseOrReason) = CLAIM_REWARD_PRECOMPILE_MOCK_ADDRESS.call(
            abi.encodeWithSelector(CLAIM_REWARD_FUNCTION_SELECTOR, srcChainId, token, withdrawer, amount)
        );

        uint256 lastlyUpdatedRewardBalance;
        if (success) {
            (, lastlyUpdatedRewardBalance) = abi.decode(responseOrReason, (bool, uint256));
        }
        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, lastlyUpdatedRewardBalance));
    }

    function requestDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        if (payload.length != DELEGATE_REQUEST_LENGTH) {
            revert InvalidRequestLength(Action.REQUEST_DELEGATE_TO, DELEGATE_REQUEST_LENGTH, payload.length);
        }

        bytes calldata token = payload[:32];
        bytes calldata delegator = payload[32:64];
        bytes calldata operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        (bool success,) = DELEGATION_PRECOMPILE_MOCK_ADDRESS.call(
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

    function requestUndelegateFrom(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        if (payload.length != UNDELEGATE_REQUEST_LENGTH) {
            revert InvalidRequestLength(Action.REQUEST_UNDELEGATE_FROM, UNDELEGATE_REQUEST_LENGTH, payload.length);
        }

        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        (bool success,) = DELEGATION_PRECOMPILE_MOCK_ADDRESS.call(
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

    function _consumeInboundNonce(uint32 srcEid, bytes32 sender, uint64 nonce) internal {
        inboundNonce[srcEid][sender] += 1;
        if (nonce != inboundNonce[srcEid][sender]) {
            revert UnexpectedInboundNonce(inboundNonce[srcEid][sender], nonce);
        }
    }

}
