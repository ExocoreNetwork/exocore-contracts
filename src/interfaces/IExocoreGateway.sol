pragma solidity ^0.8.19;

import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {IOAppReceiver} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppReceiver.sol";

interface IExocoreGateway is IOAppReceiver, IOAppCore {

    function quote(uint32 srcChainid, bytes memory _message) external view returns (uint256 nativeFee);

    function registerOrUpdateClientChain(
        uint32 clientChainId, 
        bytes32 clientChainGateway,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) external;

    function addWhitelistTokens(
        uint32 clientChainId,
        bytes32[] calldata tokens,
        uint8[] calldata decimals,
        uint256[] calldata tvlLimits,
        string[] calldata names,
        string[] calldata metaData
    ) external payable;
}
