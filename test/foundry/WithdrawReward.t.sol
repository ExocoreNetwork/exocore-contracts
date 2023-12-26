pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "../../src/interfaces/IController.sol";
import "../../src/interfaces/ITSSReceiver.sol";
import "forge-std/console.sol";

contract WithdrawRewardTest is ExocoreDeployer {
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event RequestSent(GatewayStorage.Action indexed act);
    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event Packet(uint16, address, address, uint64, bytes);

    uint constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200000;

    function test_WithdrawRewardByLayerZero() public {
        Player memory withdrawer = players[0];

        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 withdrawAmount = 1000;

        // -- withdraw reward workflow -- 

        // first user call client chain gateway to withdraw

        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        bytes memory withdrawRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE,
            bytes32(bytes20(address(restakeToken))), 
            bytes32(bytes20(withdrawer.addr)), 
            withdrawAmount
        );
        emit Packet(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway),
            uint64(1),
            withdrawRequestPayload
        );
        clientGateway.withdrawRewardFromExocore(address(restakeToken), withdrawAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        bytes memory withdrawResponsePayload = abi.encodePacked(
            GatewayStorage.Action.RESPOND,
            uint64(1), 
            true,
            uint256(1234)
        );
        emit Packet(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway),
            uint64(1),
            withdrawResponsePayload
        );
        exocoreLzEndpoint.receivePayload(
            clientChainId,
            abi.encodePacked(address(clientGateway), address(exocoreGateway)),
            address(exocoreGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            withdrawRequestPayload
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit WithdrawRewardResult(true, address(restakeToken), withdrawer.addr, withdrawAmount);
        clientChainLzEndpoint.receivePayload(
            exocoreChainId,
            abi.encodePacked(address(exocoreGateway), address(clientGateway)),
            address(clientGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            withdrawResponsePayload
        );
    }
}