pragma solidity ^0.8.19;

contract ControllerStorage {
    mapping(address => bool) public tokenWhitelist;
    mapping(address => address) public tokenVaults;
    address public gateway;
    address public ExocoreGateway;
    address public admin;
    uint16 public ExocoreChainID;

    uint256[40] private __gap;
}