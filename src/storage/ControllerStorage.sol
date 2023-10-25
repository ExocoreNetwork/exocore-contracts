pragma solidity ^0.8.19;

import {IGateway} from "../interfaces/IGateway.sol";
import {IVault} from "../interfaces/IVault.sol";

contract ControllerStorage {
    mapping(address => bool) public tokenWhitelist;
    mapping(address => IVault) public tokenVaults;
    IGateway public gateway;
    IGateway public ExocoreGateway;
    address payable public admin;
    uint16 public ExocoreChainID;

    uint256[40] private __gap;
}