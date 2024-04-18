pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "../../src/interfaces/ITSSReceiver.sol";
import {ILSTRestakingController} from "../../src/interfaces/ILSTRestakingController.sol";

import "forge-std/console.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";

contract DepositWithdrawPrincipleTest is ExocoreDeployer {
    using AddressCast for address;

    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawPrincipleResult(
        bool indexed success, address indexed token, address indexed withdrawer, uint256 amount
    );
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event MessageSent(GatewayStorage.Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);
    event MessageProcessed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event NewPacket(uint32, address, bytes32, uint64, bytes);

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200000;

    function test_DepositWithdrawByLayerZero() public {
        Player memory depositor = players[0];
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(depositor.addr, 1000000);
        vm.stopPrank();

        // Commented for testing 0 relay fee
        deal(depositor.addr, 1e22);
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);

        uint256 depositAmount = 10000;
        uint256 lastlyUpdatedPrincipleBalance;

        // -- deposit workflow test --

        vm.startPrank(depositor.addr);
        restakeToken.approve(address(vault), type(uint256).max);

        // first user call client chain gateway to deposit

        // estimate l0 relay fee that the user should pay
        bytes memory depositRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(depositor.addr)),
            depositAmount
        );
        uint256 depositRequestNativeFee = clientGateway.quote(depositRequestPayload);
        bytes32 depositRequestId = generateUID(1, true);
        // depositor should transfer deposited token to vault
        vm.expectEmit(true, true, false, true, address(restakeToken));
        emit Transfer(depositor.addr, address(vault), depositAmount);
        // client chain layerzero endpoint should emit the message packet including deposit payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            uint64(1),
            depositRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_DEPOSIT, depositRequestId, uint64(1), depositRequestNativeFee);
        clientGateway.deposit{value: depositRequestNativeFee}(address(restakeToken), depositAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        lastlyUpdatedPrincipleBalance = depositAmount;
        bytes memory depositResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, uint64(1), true, lastlyUpdatedPrincipleBalance);
        uint256 depositResponseNativeFee = exocoreGateway.quote(clientChainId, depositResponsePayload);
        bytes32 depositResponseId = generateUID(1, false);
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(1),
            depositResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, depositResponseId, uint64(1), depositResponseNativeFee);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(1)),
            address(exocoreGateway),
            depositRequestId,
            depositRequestPayload,
            bytes("")
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositResult(true, address(restakeToken), depositor.addr, depositAmount);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), uint64(1)),
            address(clientGateway),
            depositResponseId,
            depositResponsePayload,
            bytes("")
        );

        // -- withdraw principle workflow --

        uint256 withdrawAmount = 100;

        // first user call client chain gateway to withdraw

        // estimate l0 relay fee that the user should pay
        bytes memory withdrawRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(depositor.addr)),
            withdrawAmount
        );
        uint256 withdrawRequestNativeFee = clientGateway.quote(withdrawRequestPayload);
        bytes32 withdrawRequestId = generateUID(2, true);
        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            uint64(2),
            withdrawRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
            withdrawRequestId,
            uint64(2),
            withdrawRequestNativeFee
        );
        clientGateway.withdrawPrincipleFromExocore{value: withdrawRequestNativeFee}(
            address(restakeToken), withdrawAmount
        );

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        lastlyUpdatedPrincipleBalance -= withdrawAmount;
        bytes memory withdrawResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, uint64(2), true, lastlyUpdatedPrincipleBalance);
        uint256 withdrawResponseNativeFee = exocoreGateway.quote(clientChainId, withdrawResponsePayload);
        bytes32 withdrawResponseId = generateUID(2, false);
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(2),
            withdrawResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, withdrawResponseId, uint64(2), withdrawResponseNativeFee);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(2)),
            address(exocoreGateway),
            withdrawRequestId,
            withdrawRequestPayload,
            bytes("")
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit WithdrawPrincipleResult(true, address(restakeToken), depositor.addr, withdrawAmount);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), uint64(2)),
            address(clientGateway),
            withdrawResponseId,
            withdrawResponsePayload,
            bytes("")
        );
    }

    function test_TSSReceiver() public {
        Player memory depositor = players[0];
        Player memory relayer = players[1];
        uint256 depositAmount = 10000;
        uint256 withdrawAmount = 100;
        uint256 lastlyUpdatedPrincipleBalance;

        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(depositor.addr, 1000000);
        vm.stopPrank();
        deal(depositor.addr, 1e22);
        deal(relayer.addr, 1e22);
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);

        // -- deposit workflow test --

        vm.startPrank(depositor.addr);
        restakeToken.approve(address(vault), type(uint256).max);

        // first user call client chain gateway to deposit

        // estimate l0 relay fee that the user should pay
        bytes memory depositRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(depositor.addr)),
            depositAmount
        );
        uint256 depositRequestNativeFee = clientGateway.quote(depositRequestPayload);
        bytes32 depositRequestId = generateUID(1, true);
        // depositor should transfer deposited token to vault
        vm.expectEmit(true, true, false, true, address(restakeToken));
        emit Transfer(depositor.addr, address(vault), depositAmount);
        // client chain layerzero endpoint should emit the message packet including deposit payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            uint64(1),
            depositRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_DEPOSIT, depositRequestId, uint64(1), depositRequestNativeFee);
        clientGateway.deposit{value: depositRequestNativeFee}(address(restakeToken), depositAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        lastlyUpdatedPrincipleBalance = depositAmount;
        bytes memory depositResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, uint64(1), true, lastlyUpdatedPrincipleBalance);
        uint256 depositResponseNativeFee = exocoreGateway.quote(clientChainId, depositResponsePayload);
        bytes32 depositResponseId = generateUID(1, false);
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(1),
            depositResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, depositResponseId, uint64(1), depositResponseNativeFee);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(1)),
            address(exocoreGateway),
            depositRequestId,
            depositRequestPayload,
            bytes("")
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositResult(true, address(restakeToken), depositor.addr, depositAmount);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), uint64(1)),
            address(clientGateway),
            depositResponseId,
            depositResponsePayload,
            bytes("")
        );

        assertUpdateBalances(relayer, depositor, depositAmount, withdrawAmount);
    }

    function assertUpdateBalances(
        Player memory relayer,
        Player memory depositor,
        uint256 depositAmount,
        uint256 withdrawAmount
    ) internal {
        vm.chainId(clientChainId);
        vm.startPrank(relayer.addr);
        ILSTRestakingController.TokenBalanceUpdateInfo[] memory tokenBalances = new ILSTRestakingController.TokenBalanceUpdateInfo[](1);
        tokenBalances[0] = ILSTRestakingController.TokenBalanceUpdateInfo({
            token: address(restakeToken),
            lastlyUpdatedPrincipleBalance: depositAmount - withdrawAmount,
            lastlyUpdatedRewardBalance: 0,
            unlockPrincipleAmount: withdrawAmount,
            unlockRewardAmount: 0
        });
        ILSTRestakingController.UserBalanceUpdateInfo[] memory userBalances = new ILSTRestakingController.UserBalanceUpdateInfo[](1);
        userBalances[0] =
            ILSTRestakingController.UserBalanceUpdateInfo({user: depositor.addr, updatedAt: 1, tokenBalances: tokenBalances});
        (ITSSReceiver.InterchainMsg memory _msg, bytes memory signature) = prepareEVSMsgAndSignature(userBalances);

        vm.expectEmit(false, false, false, true, address(clientGateway));
        emit MessageProcessed(exocoreChainId, bytes("0x"), 1, _msg.payload);
        clientGateway.receiveInterchainMsg(_msg, signature);
        assertEq(vault.withdrawableBalances(depositor.addr), withdrawAmount);
        assertEq(vault.principleBalances(depositor.addr), depositAmount - withdrawAmount);
        assertEq(vault.rewardBalances(depositor.addr), 0);
        assertEq(vault.totalDepositedPrincipleAmount(depositor.addr), depositAmount);
        assertEq(vault.totalUnlockPrincipleAmount(depositor.addr), withdrawAmount);
    }

    function prepareEVSMsgAndSignature(ILSTRestakingController.UserBalanceUpdateInfo[] memory userBalances)
        internal
        view
        returns (ITSSReceiver.InterchainMsg memory _msg, bytes memory signature)
    {
        bytes memory args = abi.encode(userBalances);
        bytes memory payload = abi.encodePacked(GatewayStorage.Action.UPDATE_USERS_BALANCES, args);
        _msg = ITSSReceiver.InterchainMsg({
            srcChainID: exocoreChainId,
            srcAddress: bytes("0x"),
            dstChainID: clientChainId,
            dstAddress: abi.encodePacked(bytes20(address(clientGateway))),
            nonce: 1,
            payload: payload
        });
        bytes32 digest = keccak256(
            abi.encodePacked(
                _msg.srcChainID, _msg.srcAddress, _msg.dstChainID, _msg.dstAddress, _msg.nonce, _msg.payload
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(exocoreValidatorSet.privateKey, digest);
        signature = abi.encodePacked(r, s, v);
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
