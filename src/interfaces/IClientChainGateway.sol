pragma solidity ^0.8.19;

import {IOAppReceiver} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppReceiver.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {IController} from "./IController.sol";
import {ITokenWhitelister} from "./ITokenWhitelister.sol";
import {ITSSReceiver} from "./ITSSReceiver.sol";

interface IClientChainGateway is IOAppReceiver, IOAppCore, IController, ITokenWhitelister, ITSSReceiver {
    function quote(bytes memory _message) external view returns (uint256 nativeFee);
}
