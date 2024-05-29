pragma solidity ^0.8.19;

import {Bootstrap} from "../src/core/Bootstrap.sol";

import "forge-std/Script.sol";
import {BaseScript} from "./BaseScript.sol";

contract SetBootstrapTime is BaseScript {
    address bootstrapAddr;

    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory deployedContracts = vm.readFile("script/deployedBootstrapOnly.json");
        bootstrapAddr = stdJson.readAddress(deployedContracts, ".clientChain.bootstrap");

        clientChain = vm.createSelectFork(clientChainRPCURL);
    }

    function run() public {
        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);

        Bootstrap bootstrap = Bootstrap(bootstrapAddr);
        bootstrap.setSpawnTime(block.timestamp + 120 seconds);

        vm.stopBroadcast();
    }
}