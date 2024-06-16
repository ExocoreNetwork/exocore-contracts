pragma solidity ^0.8.19;

import "./BaseScript.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

import {NonShortCircuitEndpointV2Mock} from "test/mocks/NonShortCircuitEndpointV2Mock.sol";

contract PrerequisitiesScript is BaseScript {

    function setUp() public virtual override {
        super.setUp();
    }

    function run() public {
        clientChain = vm.createSelectFork(clientChainRPCURL);

        vm.startBroadcast(deployer.privateKey);
        beaconOracle = EigenLayerBeaconOracle(0xd3D285cd1516038dAED61B8BF7Ae2daD63662492);
        (bool success,) =
            address(beaconOracle).call(abi.encodeWithSelector(beaconOracle.addTimestamp.selector, 1_715_918_948));
        vm.stopPrank();
    }

}
