pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "@layerzero-contracts/mocks/LZEndpointMock.sol";
import "../src/DemoSender.sol";
import "../src/DemoReceiver.sol";

contract LayerZeroTest is Test {
    EthereumGateway private sender;
    ExocoreGateway private receiver;
    LZEndpointMock private _ethLzEndpoint;
    LZEndpointMock private _exocoreLzEndpoint;

    event MsgReceivedFromEthereum(address indexed source, bytes payload);

    function setUp() public {
        _ethLzEndpoint = new LZEndpointMock(sender.EXOCORE_ID());
        _exocoreLzEndpoint = new LZEndpointMock(receiver.ETHEREUM_ID());
        sender = new EthereumGateway(address(_ethLzEndpoint));
        receiver = new ExocoreGateway(address(_exocoreLzEndpoint));

        vm.deal(address(0x1), 100 ether);
        vm.deal(address(0x2), 100 ether);
        vm.deal(address(0x3), 100 ether);

        _ethLzEndpoint.setDestLzEndpoint(address(sender), address(_exocoreLzEndpoint));
        _exocoreLzEndpoint.setDestLzEndpoint(address(receiver), address(_ethLzEndpoint));
    }

    function test_sendToReceiver() public {
        vm.startPrank(address(0x1));
        vm.expectEmit(true, false, false, true);
        emit MsgReceivedFromEthereum(address(sender), sender.PAYLOAD());
        sender.sendToExocore(payable(address(receiver)));
    }
}
