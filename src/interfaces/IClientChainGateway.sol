pragma solidity ^0.8.19;

import {IOAppReceiver} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppReceiver.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {ILSTRestakingController} from "./ILSTRestakingController.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {ITSSReceiver} from "./ITSSReceiver.sol";

interface IClientChainGateway is IOAppReceiver, IOAppCore, ILSTRestakingController, INativeRestakingController, ITSSReceiver {
    function addWhitelistToken(address _token) external;
    function removeWhitelistToken(address _token) external;
    function addTokenVaults(address[] calldata vaults) external;
    function quote(bytes memory _message) external view returns (uint256 nativeFee);
}
