pragma solidity ^0.8.19;

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import "../src/core/BeaconProxyBytecode.sol";
import {Bootstrap} from "../src/core/Bootstrap.sol";
import {ClientChainGateway} from "../src/core/ClientChainGateway.sol";

import "../src/core/ExoCapsule.sol";
import {Vault} from "../src/core/Vault.sol";
import {ICustomProxyAdmin} from "../src/interfaces/ICustomProxyAdmin.sol";

import {BaseScript} from "./BaseScript.sol";
import {ILayerZeroEndpointV2} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";

// This script uses the address in `deployedBootstrapOnly` and redeploys on top of it. For that to work, the
// modifier for the initialize function needs to be changed from `initializer` to `reinitializer(2)`. At the same
// time, the `reinitializer` in the `ClientChainGateway` will need to be changed to `3`.
contract CorrectBootstrapErrors is BaseScript {

    address wstETH;
    address proxyAddress;
    address proxyAdmin;

    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory prerequisiteContracts = vm.readFile("script/prerequisiteContracts.json");
        clientChainLzEndpoint =
            ILayerZeroEndpointV2(stdJson.readAddress(prerequisiteContracts, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "Client chain endpoint not found");
        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(prerequisiteContracts, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "Restake token not found");
        clientChain = vm.createSelectFork(clientChainRPCURL);
        // we should use the pre-requisite to save gas instead of deploying our own
        beaconOracle = EigenLayerBeaconOracle(stdJson.readAddress(prerequisiteContracts, ".clientChain.beaconOracle"));
        require(address(beaconOracle) != address(0), "Beacon oracle not found");
        // same for BeaconProxyBytecode
        beaconProxyBytecode =
            BeaconProxyBytecode(stdJson.readAddress(prerequisiteContracts, ".clientChain.beaconProxyBytecode"));
        require(address(beaconProxyBytecode) != address(0), "Beacon proxy bytecode not found");
        // wstETH on Sepolia
        // https://docs.lido.fi/deployed-contracts/sepolia/
        wstETH = stdJson.readAddress(prerequisiteContracts, ".clientChain.wstETH");
        require(wstETH != address(0), "wstETH not found");

        string memory deployed = vm.readFile("script/deployedBootstrapOnly.json");
        proxyAddress = stdJson.readAddress(deployed, ".clientChain.bootstrap");
        require(address(proxyAddress) != address(0), "bootstrap address should not be empty");
        proxyAdmin = stdJson.readAddress(deployed, ".clientChain.proxyAdmin");
        require(address(proxyAdmin) != address(0), "proxy admin address should not be empty");
        vaultImplementation = Vault(stdJson.readAddress(deployed, ".clientChain.vaultImplementation"));
        require(address(vaultImplementation) != address(0), "vault implementation should not be empty");
        vaultBeacon = UpgradeableBeacon(stdJson.readAddress(deployed, ".clientChain.vaultBeacon"));
        require(address(vaultBeacon) != address(0), "vault beacon should not be empty");
    }

    function run() public {
        address[] memory emptyList;

        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        ProxyAdmin proxyAdmin = ProxyAdmin(proxyAdmin);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint), exocoreChainId, address(vaultBeacon), address(beaconProxyBytecode)
        );
        bytes memory data = abi.encodeCall(
            Bootstrap.initialize,
            (
                exocoreValidatorSet.addr,
                // 1 week from now
                block.timestamp + 168 hours,
                2 seconds,
                emptyList,
                address(proxyAdmin)
            )
        );
        proxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(proxyAddress), address(bootstrapLogic), data);
        Bootstrap bootstrap = Bootstrap(payable(proxyAddress));
        vm.stopBroadcast();

        string memory clientChainContracts = "clientChainContracts";
        vm.serializeAddress(clientChainContracts, "lzEndpoint", address(clientChainLzEndpoint));
        vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));
        vm.serializeAddress(clientChainContracts, "wstETH", wstETH);
        vm.serializeAddress(clientChainContracts, "proxyAdmin", address(proxyAdmin));
        vm.serializeAddress(clientChainContracts, "vaultImplementation", address(vaultImplementation));
        vm.serializeAddress(clientChainContracts, "vaultBeacon", address(vaultBeacon));
        vm.serializeAddress(clientChainContracts, "beaconProxyBytecode", address(beaconProxyBytecode));
        vm.serializeAddress(clientChainContracts, "bootstrapLogic", address(bootstrapLogic));
        vm.serializeAddress(clientChainContracts, "bootstrap", address(bootstrap));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "beaconOracle", address(beaconOracle));

        string memory deployedContracts = "deployedContracts";
        string memory finalJson = vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);

        vm.writeJson(finalJson, "script/correctBootstrapErrors.json");
    }

}
