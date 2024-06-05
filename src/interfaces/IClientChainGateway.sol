pragma solidity ^0.8.19;

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {ILSTRestakingController} from "./ILSTRestakingController.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {IOAppReceiver} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppReceiver.sol";

interface IClientChainGateway is IOAppReceiver, IOAppCore, ILSTRestakingController, INativeRestakingController {

    function quote(bytes memory _message) external view returns (uint256 nativeFee);

}
