pragma solidity ^0.8.19;

import {Bootstrap} from "../src/core/Bootstrap.sol";
import {ExocoreGateway} from "../src/core/ExocoreGateway.sol";
import {Action, GatewayStorage} from "../src/storage/GatewayStorage.sol";

import {BaseScript} from "./BaseScript.sol";
import "forge-std/Script.sol";

import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/AddressCast.sol";

contract SetPeersAndUpgrade is BaseScript {

    using AddressCast for address;

    address bootstrapAddr;
    address exocoreGatewayAddr;

    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory deployed = vm.readFile("script/deployments/deployedBootstrapOnly.json");
        bootstrapAddr = stdJson.readAddress(deployed, ".clientChain.bootstrap");
        require(address(bootstrapAddr) != address(0), "bootstrap address should not be empty");
        deployed = vm.readFile("script/deployedExocoreGatewayOnly.json");
        exocoreGatewayAddr = stdJson.readAddress(deployed, ".exocore.exocoreGateway");
        require(address(exocoreGatewayAddr) != address(0), "exocore gateway address should not be empty");
        // forks
        exocore = vm.createSelectFork(exocoreRPCURL);
        clientChain = vm.createSelectFork(clientChainRPCURL);
    }

    function run() public {
        ExocoreGateway gateway = ExocoreGateway(payable(exocoreGatewayAddr));

        vm.selectFork(exocore);
        if (!useExocorePrecompileMock) {
            _bindPrecompileMocks();
        }
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        gateway.setPeer(clientChainId, bootstrapAddr.toBytes32());
        vm.stopBroadcast();

        Bootstrap bootstrap = Bootstrap(payable(bootstrapAddr));

        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        bootstrap.setPeer(exocoreChainId, address(exocoreGatewayAddr).toBytes32());
        vm.stopBroadcast();

        vm.selectFork(exocore);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        uint256 nativeFee = exocoreGateway.quote(clientChainId, abi.encodePacked(Action.REQUEST_MARK_BOOTSTRAP, ""));
        exocoreGateway.markBootstrap{value: nativeFee}(clientChainId);
    }

}
