pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";

contract ExocoreGatewayStorage is GatewayStorage {
    address constant DEPOSIT_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000804;
    address constant DELEGATION_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000805;
    bytes4 constant DEPOSIT_FUNCTION_SELECTOR = bytes4(keccak256("deposit(uint16,bytes,bytes,uint256)"));
    bytes4 constant DELEGATE_TO_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR = bytes4(keccak256("delegateToThroughClientChain(uint16,uint64,bytes,bytes,bytes,uint256)"));
    bytes4 constant UNDELEGATE_FROM_THROUGH_CLIENT_CHAIN_FUNCTION_SELECTOR = bytes4(keccak256("undelegateFromThroughClientChain(uint16,uint64,bytes,bytes,bytes,uint256)"));

    uint256[40] private __gap;
}