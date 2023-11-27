pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";

contract ExocoreGatewayStorage is GatewayStorage {
    address constant DEPOSIT_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000804;
    address constant DELEGATION_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000805;

    uint256[40] private __gap;
}