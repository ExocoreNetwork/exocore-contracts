pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "../../src/interfaces/IController.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";

import "forge-std/console.sol";

contract DelegateTest is ExocoreDeployer {
    uint constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200000;
    event Packet(uint16, address, address, uint64, bytes);

    event DelegateResult(bool indexed success, address indexed delegator, string delegatee, address token, uint256 amount);
    event DelegateRequestProcessed(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );
    event UndelegateRequestProcessed(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );

    function test_Delegation() public {
        Player memory delegator = players[0];
        string memory operatorAddress = "evmos1v4s6vtjpmxwu9rlhqms5urzrc3tc2ae2gnuqhc";
        
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 delegateAmount = 10000;

        // -- delegate workflow test -- 

        vm.startPrank(delegator.addr);

        // first user call client chain gateway to delegate

        // client chain layerzero endpoint should emit the message packet including delegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        bytes memory delegateRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DELEGATE_TO,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            bytes(operatorAddress),  
            delegateAmount
        );
        emit Packet(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway),
            uint64(1),
            delegateRequestPayload
        );
        clientGateway.delegateTo(operatorAddress, address(restakeToken), delegateAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // DelegationMock contract function should receive correct params
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit DelegateRequestProcessed(
            clientChainId,
            uint64(1),
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            operatorAddress,
            delegateAmount
        ); 
        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        bytes memory delegateResponsePayload = abi.encodePacked(
            GatewayStorage.Action.RESPOND,
            uint64(1), 
            true
        );
        emit Packet(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway),
            uint64(1),
            delegateResponsePayload
        );
        exocoreLzEndpoint.receivePayload(
            clientChainId,
            abi.encodePacked(address(clientGateway), address(exocoreGateway)),
            address(exocoreGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            delegateRequestPayload
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DelegateResult(true, delegator.addr, operatorAddress, address(restakeToken), delegateAmount);
        clientChainLzEndpoint.receivePayload(
            exocoreChainId,
            abi.encodePacked(address(exocoreGateway), address(clientGateway)),
            address(clientGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            delegateResponsePayload
        );
    }
}