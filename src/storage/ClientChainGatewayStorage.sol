pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";
import {GatewayStorage} from "./GatewayStorage.sol";

contract ClientChainGatewayStorage is GatewayStorage {
    uint256 lastMessageNonce;

    mapping(address => bool) public whitelistTokens;
    mapping(address => IVault) public tokenVaults;
    uint16 public ExocoreChainID;

    uint256[40] private __gap;
}