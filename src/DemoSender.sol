pragma solidity ^0.8.22

import "@layerzero-contracts/lzApp/NonblockingLzApp.sol";

contract Gateway_Ethereum is NonBlockingLzApp {
    bytes public constant PAYLOAD = "message sent to Exocore";
    uint16 public constant EXOCORE_ID = 0;

    event MsgSentToExocore(address destination, bytes payload);
    event MsgReceivedFromExocore(address source, bytes payload);
    
    constructor(address _lzEndpoint) NonblockingLzApp(_lzEndpoint) {}

    function sendToExocore(address destination) public {
        _lzSend(EXOCORE_ID, PAYLOAD, destination, bytes(""), msg.value);
    }

    function _nonblockingLzReceived(uint16, bytes memory, uint64, bytes memory) internal override {
        emit MsgReceivedFromExocore(address(0x0), bytes(""));
    }

    function estimateFee(uint16 _dstChainId, bool _useZro, bytes calldata _adapterParams) public view returns (uint nativeFee, uint zroFee) {
        return lzEndpoint.estimateFees(_dstChainId, address(this), PAYLOAD, _useZro, _adapterParams);
    }
}