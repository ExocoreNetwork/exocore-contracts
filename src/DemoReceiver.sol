pragma solidity ^0.8.19;

import "@layerzero-contracts/lzApp/NonblockingLzApp.sol";

contract ExocoreGateway is NonblockingLzApp {
    bytes public constant PAYLOAD = "message sent to Ethereum";
    uint16 public constant ETHEREUM_ID = 0;

    event MsgSentToEthereum(address indexed destination, bytes payload);
    event MsgReceivedFromEthereum(address indexed source, bytes payload);

    constructor(address _lzEndpoint) NonblockingLzApp(_lzEndpoint) {}

    function sendToExocore(address payable destination) public payable {
        _lzSend(ETHEREUM_ID, PAYLOAD, destination, address(0x0), bytes(""), msg.value);
    }

    function _nonblockingLzReceive(uint16, bytes memory, uint64, bytes memory) internal override {
        emit MsgReceivedFromEthereum(address(0x0), bytes(""));
    }

    function estimateFee(uint16 _dstChainId, bool _useZro, bytes calldata _adapterParams)
        public
        view
        returns (uint256 nativeFee, uint256 zroFee)
    {
        return lzEndpoint.estimateFees(_dstChainId, address(this), PAYLOAD, _useZro, _adapterParams);
    }
}
