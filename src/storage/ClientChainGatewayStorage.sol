pragma solidity ^0.8.19;

import {BootstrapStorage} from "./BootstrapStorage.sol";

contract ClientChainGatewayStorage is BootstrapStorage {
    uint256 lastMessageNonce;
    mapping(uint64 => bytes) public registeredRequests;
    mapping(uint64 => Action) public registeredRequestActions;
    mapping(Action => bytes4) public registeredResponseHooks;

    uint64 outboundNonce;
    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) inboundNonce;

    uint128 constant DESTINATION_GAS_LIMIT = 500000;
    uint128 constant DESTINATION_MSG_VALUE = 0;

    event MessageProcessed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event MessageFailed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload, bytes _reason);
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawPrincipleResult(
        bool indexed success, address indexed token, address indexed withdrawer, uint256 amount
    );
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event DelegateResult(
        bool indexed success, address indexed delegator, string delegatee, address token, uint256 amount
    );
    event UndelegateResult(
        bool indexed success, address indexed undelegator, string indexed undelegatee, address token, uint256 amount
    );

    event UnsupportedRequestEvent(Action act);

    error UnauthorizedSigner();
    error UnsupportedResponse(Action act);
    error RequestOrResponseExecuteFailed(Action act, uint64 nonce, bytes reason);
    error ActionFailed(Action act, uint64 nonce);
    error UnexpectedResponse(uint64 nonce);

    uint256[40] private __gap;
}
