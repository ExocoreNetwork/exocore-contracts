pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";

contract ExocoreGatewayStorage is GatewayStorage {
    // bytes32 token + bytes32 depositor + uint256 amount
    uint256 constant DEPOSIT_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 constant DELEGATE_REQUEST_LENGTH = 138;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 constant UNDELEGATE_REQUEST_LENGTH = 138;
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 constant WITHDRAW_PRINCIPLE_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 constant CLAIM_REWARD_REQUEST_LENGTH = 96;

    uint128 constant DESTINATION_GAS_LIMIT = 500000;
    uint128 constant DESTINATION_MSG_VALUE = 0;

    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) inboundNonce;
    mapping(uint16 id => bool) chainToBootstrapped;

    event ExocorePrecompileError(address indexed precompile, uint64 nonce);

    error RequestExecuteFailed(Action act, uint64 nonce, bytes reason);
    error PrecompileCallFailed(bytes4 selector_, bytes reason);
    error InvalidRequestLength(Action act, uint256 expectedLength, uint256 actualLength);
    error DepositRequestShouldNotFail(uint32 srcChainId, uint64 lzNonce);

    uint256[40] private __gap;
}
