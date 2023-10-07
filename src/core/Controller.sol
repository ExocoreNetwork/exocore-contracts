pragma solidity ^0.8.19;

import {ControllerStorage} from "../storage/ControllerStorage.sol";
import {IController} from "../interfaces/IController.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Controller is ControllerStorage, IController {
    
}