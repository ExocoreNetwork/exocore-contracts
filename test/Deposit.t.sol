pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../src/core/ExocoreReceiver.sol";
import "../src/storage/GatewayStorage.sol";
import "forge-std/console.sol";

contract DepositTest is ExocoreDeployer {
    event InterchainMsgReceived(
        uint16 indexed srcChainID,
        bytes indexed srcChainAddress,
        uint64 indexed nonce,
        bytes payload
    );
    event SetTrustedRemote(uint16 _remoteChainId, bytes _path);
    event Transfer(address indexed from, address indexed to, uint256 amount);

    function test_DepositWithdraw() public {
        // -- deposit workflow test -- 

        address depositor = accounts[0];
        vm.startPrank(ExocoreValidatorSetAddress);
        restakeToken.transfer(depositor, 1000000);
        vm.expectEmit(false, false, false, true);
        emit SetTrustedRemote(exocoreChainID, abi.encodePacked(address(exocoreReceiver), address(gateway)));
        gateway.setTrustedRemote(exocoreChainID, abi.encodePacked(address(exocoreReceiver), address(gateway)));
        vm.expectEmit(false, false, false, true);
        emit SetTrustedRemote(clientChainID, abi.encodePacked(address(gateway), address(exocoreReceiver)));
        exocoreReceiver.setTrustedRemote(clientChainID, abi.encodePacked(address(gateway), address(exocoreReceiver)));
        vm.stopPrank();

        vm.startPrank(depositor);
        deal(address(gateway), 1e22);
        restakeToken.approve(address(vault), type(uint256).max);
        bytes memory payload = abi.encodePacked(GatewayStorage.Action.DEPOSIT, bytes32(bytes20(address(restakeToken))), bytes32(bytes20(depositor)), uint256(10000));
        vm.expectEmit(true, true, false, true);
        emit Transfer(depositor, address(vault), uint256(10000));

        // assert that exocoreReceiver would receive the message and save the msg as event
        vm.expectEmit(true, true, true, true, address(exocoreReceiver));
        emit InterchainMsgReceived(uint16(clientChainID), abi.encodePacked(bytes20(address(gateway))), 1, payload);

        gateway.deposit(address(restakeToken), 10000);
    }
}