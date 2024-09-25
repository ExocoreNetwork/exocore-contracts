pragma solidity ^0.8.19;

import "../../src/core/ExocoreGateway.sol";
import {Action, GatewayStorage} from "../../src/storage/GatewayStorage.sol";
import "./ExocoreDeployer.t.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract WithdrawRewardTest is ExocoreDeployer {

    using AddressCast for address;

    event ClaimRewardResult(bool indexed success, bytes32 indexed token, bytes32 indexed withdrawer, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);

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
        bytes memory withdrawRequestPayload = abi.encodePacked(
            Action.REQUEST_CLAIM_REWARD,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(withdrawer.addr)),
            withdrawAmount
        );
        uint256 requestNativeFee = clientGateway.quote(withdrawRequestPayload);
        bytes32 requestId = generateUID(outboundNonces[clientChainId], true);
        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            outboundNonces[clientChainId],
            withdrawRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
<<<<<<< HEAD
        emit MessageSent(
            GatewayStorage.Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE,
            requestId,
            outboundNonces[clientChainId]++,
            requestNativeFee
        );
=======
        emit MessageSent(Action.REQUEST_CLAIM_REWARD, requestId, withdrawRequestNonce, requestNativeFee);
>>>>>>> 68fba84 (feat: use ActionAttributes lib)

        vm.startPrank(withdrawer.addr);
        clientGateway.withdrawRewardFromExocore{value: requestNativeFee}(address(restakeToken), withdrawAmount);
        vm.stopPrank();

        // second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        bytes memory withdrawResponsePayload =
<<<<<<< HEAD
            abi.encodePacked(GatewayStorage.Action.RESPOND, outboundNonces[clientChainId] - 1, true, uint256(1234));
=======
            abi.encodePacked(Action.RESPOND, withdrawRequestNonce, true, uint256(1234));
>>>>>>> 68fba84 (feat: use ActionAttributes lib)
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, withdrawResponsePayload);
        bytes32 responseId = generateUID(outboundNonces[exocoreChainId], false);

        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            outboundNonces[exocoreChainId],
            withdrawResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, outboundNonces[exocoreChainId]++, responseNativeFee);

        // exocore gateway should emit WithdrawRewardResult event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit ClaimRewardResult(
            true, bytes32(bytes20(address(restakeToken))), bytes32(bytes20(withdrawer.addr)), withdrawAmount
        );

        vm.expectEmit(address(exocoreGateway));
        emit MessageExecuted(
            GatewayStorage.Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE, inboundNonces[exocoreChainId]++
        );

        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), inboundNonces[exocoreChainId] - 1),
            address(exocoreGateway),
            requestId,
            withdrawRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        // third layerzero relayers should watch the response message packet and relay the message to source chain
        // endpoint

        // client chain gateway should execute the response hook and emit RequestFinished event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit RequestFinished(
            GatewayStorage.Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE, outboundNonces[clientChainId] - 1, true
        );

        vm.expectEmit(address(clientGateway));
        emit MessageExecuted(GatewayStorage.Action.RESPOND, inboundNonces[clientChainId]++);

        vm.startPrank(relayer.addr);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), inboundNonces[clientChainId] - 1),
            address(clientGateway),
            responseId,
            withdrawResponsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

}
