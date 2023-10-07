pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";

contract ControllerStorage {
    mapping(address => bool) public tokenWhitelist;
    mapping(address => IVault) public tokenVaults;

    uint256[40] private __gap;
}