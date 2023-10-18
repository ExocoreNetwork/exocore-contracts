pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IController} from "../interfaces/IController.sol";

contract GatewayStorage {
    address public ExocoreValidatorSetPubkey;
    IController public controller;

    uint256 public lzFee;
}