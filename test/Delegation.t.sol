pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../src/core/ExocoreGateway.sol";
import "../src/storage/GatewayStorage.sol";
import "../src/interfaces/IController.sol";
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

    function test_Delegation() public {
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
        restakeToken.approve(address(vault), type(uint256).max);
        uint256 depositAmount = 10000;
        bytes memory payload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT, 
            bytes32(bytes20(address(restakeToken))), 
            bytes32(bytes20(depositor.addr)), 
            depositAmount
        );
        vm.expectEmit(true, true, false, true);
        emit Transfer(depositor.addr, address(vault), depositAmount);

        // assert that exocoreGateway should receive the message and save the msg as event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit InterchainMsgReceived(clientChainID, abi.encodePacked(bytes20(address(clientGateway))), 1, payload);
        clientGateway.deposit(address(restakeToken), depositAmount);

        // -- delegate workflow -- 

        uint256 delegateAmount = 100;
        Player memory operator = players[1];
        payload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DELEGATE_TO,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(operator.addr)),
            bytes32(bytes20(depositor.addr)),
            delegateAmount
        );
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit InterchainMsgReceived(clientChainID, abi.encodePacked(bytes20(address(clientGateway))), 2, payload);
        clientGateway.delegateTo(bytes32(bytes20(operator.addr)), address(restakeToken), delegateAmount);
    }
}