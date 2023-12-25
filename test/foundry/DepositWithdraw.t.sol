pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "../../src/interfaces/IController.sol";
import "../../src/interfaces/ITSSReceiver.sol";
import "forge-std/console.sol";

contract DepositWithdrawTest is ExocoreDeployer {
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event SetTrustedRemote(uint16 _remoteChainId, bytes _path);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event RequestSent(GatewayStorage.Action indexed act);
    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);

    function test_DepositWithdrawByLayerZero() public {
        // -- deposit workflow test -- 

        vm.chainId(clientChainID);

        Player memory depositor = players[0];
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(depositor.addr, 1000000);
        vm.expectEmit(false, false, false, true);
        emit SetTrustedRemote(exocoreChainID, abi.encodePacked(address(exocoreGateway), address(clientGateway)));
        clientGateway.setTrustedRemote(exocoreChainID, abi.encodePacked(address(exocoreGateway), address(clientGateway)));
        vm.expectEmit(false, false, false, true);
        emit SetTrustedRemote(clientChainID, abi.encodePacked(address(clientGateway), address(exocoreGateway)));
        exocoreGateway.setTrustedRemote(clientChainID, abi.encodePacked(address(clientGateway), address(exocoreGateway)));
        vm.stopPrank();

        vm.startPrank(depositor.addr);
        deal(address(clientGateway), 1e22);
        deal(address(exocoreGateway), 1e22);
        restakeToken.approve(address(vault), type(uint256).max);
        uint256 depositAmount = 10000;
        vm.expectEmit(true, true, false, true);
        emit Transfer(depositor.addr, address(vault), depositAmount);

        // assert that exocoreGateway should receive the message and send back the response
        // client chain gateway should receive the response and emit the coresponding event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositResult(true, address(restakeToken), depositor.addr, depositAmount);
        clientGateway.deposit(address(restakeToken), depositAmount);

        // -- withdraw workflow -- 

        uint256 withdrawAmount = 100;

        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit WithdrawResult(true, address(restakeToken), depositor.addr, withdrawAmount);
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit RequestSent(GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE);
        clientGateway.withdrawPrincipleFromExocore(address(restakeToken), withdrawAmount);
        vm.stopPrank();
    }

    function test_TSSReceiver() public {
        Player memory depositor = players[0];
        Player memory relayer = players[1];
        uint256 depositAmount = 10000;
        uint256 withdrawAmount = 100;

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
        emit MessageProcessed(exocoreChainID, bytes("0x"), 1, _msg.payload);
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
            srcChainID: exocoreChainID, 
            srcAddress: bytes("0x"), 
            dstChainID: clientChainID, 
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