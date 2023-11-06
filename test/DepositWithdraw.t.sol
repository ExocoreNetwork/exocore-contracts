pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../src/core/ExocoreReceiver.sol";
import "../src/storage/GatewayStorage.sol";
import "../src/interfaces/IGateway.sol";
import "forge-std/console.sol";

contract DepositWithdrawTest is ExocoreDeployer {
    event InterchainMsgReceived(
        uint16 indexed srcChainID,
        bytes indexed srcChainAddress,
        uint64 indexed nonce,
        bytes payload
    );
    event SetTrustedRemote(uint16 _remoteChainId, bytes _path);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event RequestSent(GatewayStorage.Action indexed act, uint16 indexed dstChainID, address indexed  dstAddress, bytes payload);
    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);

    function test_DepositWithdraw() public {
        // -- deposit workflow test -- 

        vm.chainId(clientChainID);

        Player memory depositor = players[0];
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(depositor.addr, 1000000);
        vm.expectEmit(false, false, false, true);
        emit SetTrustedRemote(exocoreChainID, abi.encodePacked(address(exocoreReceiver), address(gateway)));
        gateway.setTrustedRemote(exocoreChainID, abi.encodePacked(address(exocoreReceiver), address(gateway)));
        vm.expectEmit(false, false, false, true);
        emit SetTrustedRemote(clientChainID, abi.encodePacked(address(gateway), address(exocoreReceiver)));
        exocoreReceiver.setTrustedRemote(clientChainID, abi.encodePacked(address(gateway), address(exocoreReceiver)));
        vm.stopPrank();

        vm.startPrank(depositor.addr);
        deal(address(gateway), 1e22);
        restakeToken.approve(address(vault), type(uint256).max);
        uint256 depositAmount = 10000;
        bytes memory payload = abi.encodePacked(
            GatewayStorage.Action.DEPOSIT, 
            bytes32(bytes20(address(restakeToken))), 
            bytes32(bytes20(depositor.addr)), 
            depositAmount
        );
        vm.expectEmit(true, true, false, true);
        emit Transfer(depositor.addr, address(vault), depositAmount);

        // assert that exocoreReceiver should receive the message and save the msg as event
        vm.expectEmit(true, true, true, true, address(exocoreReceiver));
        emit InterchainMsgReceived(clientChainID, abi.encodePacked(bytes20(address(gateway))), 1, payload);
        gateway.deposit(address(restakeToken), depositAmount);

        // -- withdraw workflow -- 

        uint256 withdrawAmount = 100;
        payload = abi.encodePacked(
            GatewayStorage.Action.WITHDRAWPRINCIPLEFROMEXOCORE, 
            bytes32(bytes20(address(restakeToken))), 
            bytes32(bytes20(depositor.addr)), 
            withdrawAmount
        );

        vm.expectEmit(true, true, true, true, address(exocoreReceiver));
        emit InterchainMsgReceived(clientChainID, abi.encodePacked(bytes20(address(gateway))), 2, payload);
        vm.expectEmit(true, true, true, true, address(gateway));
        emit RequestSent(GatewayStorage.Action.WITHDRAWPRINCIPLEFROMEXOCORE, exocoreChainID, address(exocoreReceiver), payload);
        gateway.withdrawPrincipleFromExocore(address(restakeToken), 100);
        vm.stopPrank();

        Player memory relayer = players[1];
        vm.startPrank(relayer.addr);
        IGateway.TokenBalanceUpdateInfo[] memory tokenBalances = new IGateway.TokenBalanceUpdateInfo[](1);
        tokenBalances[0] = IGateway.TokenBalanceUpdateInfo({
            token: address(restakeToken),
            lastlyUpdatedPrincipleBalance: depositAmount - withdrawAmount,
            lastlyUpdatedRewardBalance: 0,
            unlockPrincipleAmount: withdrawAmount,
            unlockRewardAmount: 0
        });
        IGateway.UserBalanceUpdateInfo[] memory userBalances = new IGateway.UserBalanceUpdateInfo[](1);
        userBalances[0] = IGateway.UserBalanceUpdateInfo({
            user: depositor.addr,
            updatedAt: 1,
            tokenBalances: tokenBalances
        });
        bytes memory args = abi.encode(userBalances);
        payload = abi.encodePacked(GatewayStorage.Action.UPDATEUSERSBALANCE, args);
        IGateway.InterchainMsg memory _msg = IGateway.InterchainMsg({
            srcChainID: exocoreChainID, 
            srcAddress: bytes("0x"), 
            dstChainID: clientChainID, 
            dstAddress: abi.encodePacked(bytes20(address(gateway))), 
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
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(false, false, false, true, address(gateway));
        emit MessageProcessed(exocoreChainID, bytes("0x"), 1, payload);
        gateway.receiveInterchainMsg(_msg, signature);
    }
}