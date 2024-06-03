pragma solidity ^0.8.19;

import {IOAppReceiver} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppReceiver.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {ILSTRestakingController} from "./ILSTRestakingController.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {ITokenWhitelister} from "../interfaces/ITokenWhitelister.sol";

interface IClientChainGateway is
    ITokenWhitelister,
    IOAppReceiver,
    IOAppCore,
    ILSTRestakingController,
    INativeRestakingController
{
    function quote(bytes memory _message) external view returns (uint256 nativeFee);
}
