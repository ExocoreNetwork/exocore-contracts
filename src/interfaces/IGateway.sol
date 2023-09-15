pragma solidity ^0.8.19;

interface IGateway {
    struct InterchainMsg {
        uint16  dstChainID;
        bytes  dstAddress;
        bytes payload;
        address payable refundAddress;
        address payable interchainFuelAddress;
        bytes params;
    }

    event  InterchainMsgSent(
        uint16 indexed dstChainID,
        bytes indexed dstAddress,
        bytes payload,
        address refundAddress,
        address interchainFuelAddress,
        bytes params
    );

    function sendInterchainMsg(InterchainMsg calldata msg) external payable;
    function receiveInterchainMsg(InterchainMsg calldata msg) external payable;
}