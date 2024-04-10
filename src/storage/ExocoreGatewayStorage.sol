pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";

contract ExocoreGatewayStorage is GatewayStorage {
    address constant DEPOSIT_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000804;
    address constant DELEGATION_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000805;
    address constant WITHDRAW_PRINCIPLE_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000808;
    address constant CLAIM_REWARD_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000806;

    bytes4 constant DEPOSIT_FUNCTION_SELECTOR = bytes4(keccak256("depositTo(uint16,bytes,bytes,uint256)"));
    bytes4 constant DELEGATE_TO_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR =
        bytes4(keccak256("delegateToThroughClientChain(uint16,uint64,bytes,bytes,bytes,uint256)"));
    bytes4 constant UNDELEGATE_FROM_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR =
        bytes4(keccak256("undelegateFromThroughClientChain(uint16,uint64,bytes,bytes,bytes,uint256)"));
    bytes4 constant WITHDRAW_PRINCIPLE_FUNCTION_SELECTOR =
        bytes4(keccak256("withdrawPrinciple(uint16,bytes,bytes,uint256)"));
    bytes4 constant CLAIM_REWARD_FUNCTION_SELECTOR = bytes4(keccak256("claimReward(uint16,bytes,bytes,uint256)"));

    uint128 constant DESTINATION_GAS_LIMIT = 500000;
    uint128 constant DESTINATION_MSG_VALUE = 0;

    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) inboundNonce;

    event MessageSent(Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    error UnsupportedRequest(Action act);
    error RequestExecuteFailed(Action act, uint64 nonce, bytes reason);
    error PrecompileCallFailed(bytes4 selector_, bytes reason);
    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);
    error UnexpectedSourceChain(uint32 unexpectedSrcEndpointId);

    uint256[40] private __gap;
}
