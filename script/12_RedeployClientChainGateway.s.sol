pragma solidity ^0.8.19;

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import "../src/core/BeaconProxyBytecode.sol";
import {Bootstrap} from "../src/core/Bootstrap.sol";
import {ClientChainGateway} from "../src/core/ClientChainGateway.sol";
import {CustomProxyAdmin} from "../src/core/CustomProxyAdmin.sol";
import "../src/core/ExoCapsule.sol";
import {Vault} from "../src/core/Vault.sol";

import {BaseScript} from "./BaseScript.sol";

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import {ILayerZeroEndpointV2} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

contract RedeployClientChainGateway is BaseScript {

    Bootstrap bootstrap;

    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory prerequisiteContracts = vm.readFile("script/deployedBootstrapOnly.json");
        clientChainLzEndpoint =
            ILayerZeroEndpointV2(stdJson.readAddress(prerequisiteContracts, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "client chain l0 endpoint should not be empty");
        beaconOracle = EigenLayerBeaconOracle(stdJson.readAddress(prerequisiteContracts, ".clientChain.beaconOracle"));
        require(address(beaconOracle) != address(0), "beacon oracle should not be empty");
        vaultBeacon = UpgradeableBeacon(stdJson.readAddress(prerequisiteContracts, ".clientChain.vaultBeacon"));
        require(address(vaultBeacon) != address(0), "vault beacon should not be empty");
        capsuleBeacon = UpgradeableBeacon(stdJson.readAddress(prerequisiteContracts, ".clientChain.capsuleBeacon"));
        require(address(capsuleBeacon) != address(0), "capsule beacon should not be empty");
        beaconProxyBytecode =
            BeaconProxyBytecode(stdJson.readAddress(prerequisiteContracts, ".clientChain.beaconProxyBytecode"));
        require(address(beaconProxyBytecode) != address(0), "beacon proxy bytecode should not be empty");
        bootstrap = Bootstrap(stdJson.readAddress(prerequisiteContracts, ".clientChain.bootstrap"));
        require(address(bootstrap) != address(0), "bootstrap should not be empty");
        clientChain = vm.createSelectFork(clientChainRPCURL);
    }

    function run() public {
        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(beaconOracle),
            address(vaultBeacon),
            address(capsuleBeacon),
            address(beaconProxyBytecode)
        );
        // then the client chain initialization
        address[] memory emptyList;
        bytes memory initialization =
            abi.encodeWithSelector(clientGatewayLogic.initialize.selector, exocoreValidatorSet.addr, emptyList);
        bootstrap.setClientChainGatewayLogic(address(clientGatewayLogic), initialization);
        vm.stopBroadcast();

        string memory clientChainContracts = "clientChainContracts";
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "clientGatewayLogic", address(clientGatewayLogic));

        string memory deployedContracts = "deployedContracts";
        string memory finalJson = vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);

        vm.writeJson(finalJson, "script/redeployClientChainGateway.json");
    }

}
