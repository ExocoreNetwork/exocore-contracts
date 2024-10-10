pragma solidity ^0.8.19;

import "../src/core/ExoCapsule.sol";
import "./BaseScript.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "forge-std/Script.sol";

contract UpgradeExoCapsuleScript is BaseScript {

    UpgradeableBeacon capsuleBeaconContract;

    function setUp() public virtual override {
        super.setUp();

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        capsuleBeaconContract =
            UpgradeableBeacon((stdJson.readAddress(deployedContracts, ".clientChain.capsuleBeacon")));
        require(address(capsuleBeaconContract) != address(0), "capsuleBeacon address should not be empty");
        clientChain = vm.createSelectFork(clientChainRPCURL);
    }

    function run() public {
        vm.selectFork(clientChain);
        vm.startBroadcast(deployer.privateKey);
        console.log("owner", capsuleBeaconContract.owner());
        ExoCapsule capsule = new ExoCapsule();
        capsuleBeaconContract.upgradeTo(address(capsule));
        vm.stopBroadcast();

        console.log("new Exocapsule Implementation address: ", address(capsule));
    }

}
