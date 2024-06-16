pragma solidity ^0.8.19;

import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "./ExocoreDeployer.t.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract WithdrawRewardTest is ExocoreDeployer {

    using AddressCast for address;

    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200_000;

    function test_WithdrawRewardByLayerZero() public {
        Player memory withdrawer = players[0];
        Player memory relayer = players[1];

        deal(withdrawer.addr, 1e22);
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 withdrawAmount = 1000;

        // before withdraw we should add whitelist tokens
        test_AddWhitelistTokens();

        // -- withdraw reward workflow --

        // first user call client chain gateway to withdraw

        // estimate l0 relay fee that the user should pay
        uint64 withdrawRequestNonce = 2;
        bytes memory withdrawRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(withdrawer.addr)),
            withdrawAmount
        );
        uint256 requestNativeFee = clientGateway.quote(withdrawRequestPayload);
        bytes32 requestId = generateUID(withdrawRequestNonce, true);
        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            withdrawRequestNonce,
            withdrawRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE,
            requestId,
            withdrawRequestNonce,
            requestNativeFee
        );

        vm.startPrank(withdrawer.addr);
        clientGateway.withdrawRewardFromExocore{value: requestNativeFee}(address(restakeToken), withdrawAmount);
        vm.stopPrank();

        // second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        uint64 withdrawResponseNonce = 2;
        bytes memory withdrawResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, withdrawRequestNonce, true, uint256(1234));
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, withdrawResponsePayload);
        bytes32 responseId = generateUID(withdrawResponseNonce, false);

        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            withdrawResponseNonce,
            withdrawResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, withdrawResponseNonce, responseNativeFee);

        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), withdrawRequestNonce),
            address(exocoreGateway),
            requestId,
            withdrawRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        // third layerzero relayers should watch the response message packet and relay the message to source chain
        // endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit WithdrawRewardResult(true, address(restakeToken), withdrawer.addr, withdrawAmount);

        vm.startPrank(relayer.addr);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), withdrawResponseNonce),
            address(clientGateway),
            responseId,
            withdrawResponsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

}
