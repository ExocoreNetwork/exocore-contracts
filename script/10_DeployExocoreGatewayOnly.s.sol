pragma solidity ^0.8.19;

import {ILayerZeroEndpointV2} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {ExocoreGateway} from "../src/core/ExocoreGateway.sol";

import {BaseScript} from "./BaseScript.sol";
import "forge-std/Script.sol";

contract DeployExocoreGatewayOnly is BaseScript {

    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory prerequisites = vm.readFile("script/deployments/prerequisiteContracts.json");
        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(prerequisites, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocore l0 endpoint should not be empty");
        // fork
        exocore = vm.createSelectFork(exocoreRPCURL);
    }

    function run() public {
        vm.selectFork(exocore);
        vm.startBroadcast(deployer.privateKey);

        ProxyAdmin exocoreProxyAdmin = new ProxyAdmin();
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway(address(exocoreLzEndpoint));
        exocoreGateway = ExocoreGateway(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(exocoreGatewayLogic),
                        address(exocoreProxyAdmin),
                        abi.encodeWithSelector(
                            exocoreGatewayLogic.initialize.selector, payable(exocoreValidatorSet.addr)
                        )
                    )
                )
            )
        );

        vm.stopBroadcast();

        string memory exocoreContracts = "exocoreContracts";
        vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));
        vm.serializeAddress(exocoreContracts, "exocoreGatewayLogic", address(exocoreGatewayLogic));
        vm.serializeAddress(exocoreContracts, "exocoreProxyAdmin", address(exocoreProxyAdmin));
        string memory exocoreContractsOutput =
            vm.serializeAddress(exocoreContracts, "exocoreGateway", address(exocoreGateway));

        string memory deployedContracts = "deployedContracts";
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);

        vm.writeJson(finalJson, "script/deployments/deployedExocoreGatewayOnly.json");
    }

}
