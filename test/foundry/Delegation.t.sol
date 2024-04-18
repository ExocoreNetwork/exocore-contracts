pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "forge-std/console.sol";

contract DelegateTest is ExocoreDeployer {
    using AddressCast for address;

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200000;

    event NewPacket(uint32, address, bytes32, uint64, bytes);
    event MessageSent(GatewayStorage.Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    event DelegateResult(
        bool indexed success, address indexed delegator, string delegatee, address token, uint256 amount
    );
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

        deal(delegator.addr, 1e22);
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 delegateAmount = 10000;

        // -- delegate workflow test --

        vm.startPrank(delegator.addr);

        // first user call client chain gateway to delegate

        // estimate l0 relay fee that would be charged from user
        bytes memory delegateRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DELEGATE_TO,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            bytes(operatorAddress),
            delegateAmount
        );
        uint256 requestNativeFee = clientGateway.quote(delegateRequestPayload);
        bytes32 requestId = generateUID(1, true);
        // client chain layerzero endpoint should emit the message packet including delegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            uint64(1),
            delegateRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_DELEGATE_TO, requestId, uint64(1), requestNativeFee);
        clientGateway.delegateTo{value: requestNativeFee}(operatorAddress, address(restakeToken), delegateAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // DelegationMock contract function should receive correct params
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit DelegateRequestProcessed(
            uint16(clientChainId),
            uint64(1),
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            operatorAddress,
            delegateAmount
        );
        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        bytes memory delegateResponsePayload = abi.encodePacked(GatewayStorage.Action.RESPOND, uint64(1), true);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, delegateResponsePayload);
        bytes32 responseId = generateUID(1, false);
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(1),
            delegateResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, uint64(1), responseNativeFee);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(1)),
            address(exocoreGateway),
            requestId,
            delegateRequestPayload,
            bytes("")
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DelegateResult(true, delegator.addr, operatorAddress, address(restakeToken), delegateAmount);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), uint64(1)),
            address(clientGateway),
            responseId,
            delegateResponsePayload,
            bytes("")
        );
    }

    function generateUID(uint64 nonce, bool fromClientChainToExocore) internal view returns (bytes32 uid) {
        if (fromClientChainToExocore) {
            uid = GUID.generate(
                nonce, clientChainId, address(clientGateway), exocoreChainId, address(exocoreGateway).toBytes32()
            );
        } else {
            uid = GUID.generate(
                nonce, exocoreChainId, address(exocoreGateway), clientChainId, address(clientGateway).toBytes32()
            );
        }
    }
}
