pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "../../src/interfaces/IController.sol";
import "../../src/interfaces/ITSSReceiver.sol";
import "forge-std/console.sol";

contract DepositWithdrawPrincipleTest is ExocoreDeployer {
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawPrincipleResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event RequestSent(GatewayStorage.Action indexed act);
    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event Packet(uint16, address, address, uint64, bytes);

    uint constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200000;

    function test_DepositWithdrawByLayerZero() public {
        Player memory depositor = players[0];
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(depositor.addr, 1000000);
        vm.stopPrank();
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 depositAmount = 10000;
        uint256 lastlyUpdatedPrincipleBalance;

        // -- deposit workflow test -- 

        vm.startPrank(depositor.addr);
        restakeToken.approve(address(vault), type(uint256).max);

        // first user call client chain gateway to deposit

        // depositor should transfer deposited token to vault
        vm.expectEmit(true, true, false, true, address(restakeToken));
        emit Transfer(depositor.addr, address(vault), depositAmount);
        // client chain layerzero endpoint should emit the message packet including deposit payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        bytes memory depositRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            bytes32(bytes20(address(restakeToken))), 
            bytes32(bytes20(depositor.addr)), 
            depositAmount
        );
        emit Packet(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway),
            uint64(1),
            depositRequestPayload
        );
        clientGateway.deposit(address(restakeToken), depositAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        lastlyUpdatedPrincipleBalance = depositAmount;
        bytes memory depositResponsePayload = abi.encodePacked(
            GatewayStorage.Action.RESPOND,
            uint64(1), 
            true,
            lastlyUpdatedPrincipleBalance
        );
        emit Packet(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway),
            uint64(1),
            depositResponsePayload
        );
        exocoreLzEndpoint.receivePayload(
            clientChainId,
            abi.encodePacked(address(clientGateway), address(exocoreGateway)),
            address(exocoreGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            depositRequestPayload
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositResult(true, address(restakeToken), depositor.addr, depositAmount);
        clientChainLzEndpoint.receivePayload(
            exocoreChainId,
            abi.encodePacked(address(exocoreGateway), address(clientGateway)),
            address(clientGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            depositResponsePayload
        );

        // -- withdraw principle workflow -- 

        uint256 withdrawAmount = 100;

        // first user call client chain gateway to withdraw

        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        bytes memory withdrawRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
            bytes32(bytes20(address(restakeToken))), 
            bytes32(bytes20(depositor.addr)), 
            withdrawAmount
        );
        emit Packet(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway),
            uint64(2),
            withdrawRequestPayload
        );
        clientGateway.withdrawPrincipleFromExocore(address(restakeToken), withdrawAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        lastlyUpdatedPrincipleBalance -= withdrawAmount;
        bytes memory withdrawResponsePayload = abi.encodePacked(
            GatewayStorage.Action.RESPOND,
            uint64(2), 
            true,
            lastlyUpdatedPrincipleBalance
        );
        emit Packet(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway),
            uint64(2),
            withdrawResponsePayload
        );
        exocoreLzEndpoint.receivePayload(
            clientChainId,
            abi.encodePacked(address(clientGateway), address(exocoreGateway)),
            address(exocoreGateway),
            uint64(2),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            withdrawRequestPayload
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit WithdrawPrincipleResult(true, address(restakeToken), depositor.addr, withdrawAmount);
        clientChainLzEndpoint.receivePayload(
            exocoreChainId,
            abi.encodePacked(address(exocoreGateway), address(clientGateway)),
            address(clientGateway),
            uint64(2),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            withdrawResponsePayload
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
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);

        // -- deposit workflow test -- 

        vm.startPrank(depositor.addr);
        restakeToken.approve(address(vault), type(uint256).max);

        // first user call client chain gateway to deposit

        // depositor should transfer deposited token to vault
        vm.expectEmit(true, true, false, true, address(restakeToken));
        emit Transfer(depositor.addr, address(vault), depositAmount);
        // client chain layerzero endpoint should emit the message packet including deposit payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        bytes memory depositRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            bytes32(bytes20(address(restakeToken))), 
            bytes32(bytes20(depositor.addr)), 
            depositAmount
        );
        emit Packet(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway),
            uint64(1),
            depositRequestPayload
        );
        clientGateway.deposit(address(restakeToken), depositAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        lastlyUpdatedPrincipleBalance = depositAmount;
        bytes memory depositResponsePayload = abi.encodePacked(
            GatewayStorage.Action.RESPOND,
            uint64(1), 
            true,
            lastlyUpdatedPrincipleBalance
        );
        emit Packet(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway),
            uint64(1),
            depositResponsePayload
        );
        exocoreLzEndpoint.receivePayload(
            clientChainId,
            abi.encodePacked(address(clientGateway), address(exocoreGateway)),
            address(exocoreGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            depositRequestPayload
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositResult(true, address(restakeToken), depositor.addr, depositAmount);
        clientChainLzEndpoint.receivePayload(
            exocoreChainId,
            abi.encodePacked(address(exocoreGateway), address(clientGateway)),
            address(clientGateway),
            uint64(1),
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            depositResponsePayload
        );

        vm.chainId(clientChainId);
        vm.startPrank(relayer.addr);
        IController.TokenBalanceUpdateInfo[] memory tokenBalances = new IController.TokenBalanceUpdateInfo[](1);
        tokenBalances[0] = IController.TokenBalanceUpdateInfo({
            token: address(restakeToken),
            lastlyUpdatedPrincipleBalance: depositAmount - withdrawAmount,
            lastlyUpdatedRewardBalance: 0,
            unlockPrincipleAmount: withdrawAmount,
            unlockRewardAmount: 0
        });
        IController.UserBalanceUpdateInfo[] memory userBalances = new IController.UserBalanceUpdateInfo[](1);
        userBalances[0] = IController.UserBalanceUpdateInfo({
            user: depositor.addr,
            updatedAt: 1,
            tokenBalances: tokenBalances
        });
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

    function prepareEVSMsgAndSignature(IController.UserBalanceUpdateInfo[] memory userBalances) internal view returns(
        ITSSReceiver.InterchainMsg memory _msg,
        bytes memory signature
    ) {
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
        bytes32 digest = keccak256(abi.encodePacked(
            _msg.srcChainID,
            _msg.srcAddress,
            _msg.dstChainID,
            _msg.dstAddress,
            _msg.nonce,
            _msg.payload
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(exocoreValidatorSet.privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }
}