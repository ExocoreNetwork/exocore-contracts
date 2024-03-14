pragma solidity ^0.8.19;

import {IOAppReceiver} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppReceiver.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";

interface IExocoreGateway is IOAppReceiver, IOAppCore {
    function quote(uint32 srcChainid, bytes memory _message) external view returns (uint256 nativeFee);
}
