pragma solidity ^0.8.19;

import {BootstrapStorage} from "./BootstrapStorage.sol";

contract ClientChainGatewayStorage is BootstrapStorage {
    mapping(uint64 => bytes) public registeredRequests;
    mapping(uint64 => Action) public registeredRequestActions;
    mapping(Action => bytes4) public registeredResponseHooks;

    uint64 outboundNonce;

    uint128 constant DESTINATION_GAS_LIMIT = 500000;
    uint128 constant DESTINATION_MSG_VALUE = 0;

    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);

    error UnsupportedResponse(Action act);
    error UnexpectedResponse(uint64 nonce);

    uint256[40] private __gap;
}
