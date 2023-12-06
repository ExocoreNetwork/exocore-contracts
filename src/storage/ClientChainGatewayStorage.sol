pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";
import {GatewayStorage} from "./GatewayStorage.sol";

contract ClientChainGatewayStorage is GatewayStorage {

    uint256 lastMessageNonce;
    mapping(address => bool) public whitelistTokens;
    mapping(address => IVault) public tokenVaults;
    mapping(uint64 => bytes) public registeredRequests;
    mapping(uint64 => Action) public registeredRequestActions;
    mapping(Action => bytes4) public registeredResponseHooks;
    uint16 public ExocoreChainID;

    uint256[40] private __gap;
}