pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../src/core/ExocoreGateway.sol";
import "../src/storage/GatewayStorage.sol";
import "../src/interfaces/IController.sol";
import "forge-std/console.sol";

contract DepositWithdrawTest is ExocoreDeployer {
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event DelegateResult(bool indexed success, address indexed delegator, bytes32 indexed delegatee, address token, uint256 amount);
    event SetTrustedRemote(uint16 _remoteChainId, bytes _path);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event RequestSent(GatewayStorage.Action indexed act);
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

        // -- delegate workflow -- 

        uint256 delegateAmount = 100;
        Player memory operator = players[1];
        
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DelegateResult(true, depositor.addr, bytes32(bytes20(operator.addr)), address(restakeToken), delegateAmount);
        clientGateway.delegateTo(bytes32(bytes20(operator.addr)), address(restakeToken), delegateAmount);
    }
}