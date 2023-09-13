pragma solidity ^0.8.22

import "@layerzero-contracts/lzApp/NonblockingLzApp.sol";

contract Gateway_Exocore is NonBlockingLzApp {
    bytes public constant PAYLOAD = "message sent to Ethereum";
    uint16 public constant ETHEREUM_ID = 0;

    event MsgSentToEthereum(address destination, bytes payload);
    event MsgReceivedFromEthereum(address source, bytes payload);
    
    constructor(address _lzEndpoint) NonblockingLzApp(_lzEndpoint) {}

    function sendToExocore(address destination) public {
        _lzSend(ETHEREUM_ID, PAYLOAD, destination, bytes(""), msg.value);
    }

    function _nonblockingLzReceived(uint16, bytes memory, uint64, bytes memory) internal override {
        emit MsgReceivedFromEthereum(address(0x0), bytes(""));
    }

    function estimateFee(uint16 _dstChainId, bool _useZro, bytes calldata _adapterParams) public view returns (uint nativeFee, uint zroFee) {
        return lzEndpoint.estimateFees(_dstChainId, address(this), PAYLOAD, _useZro, _adapterParams);
    }
}