pragma solidity ^0.8.19;

import {TransparentUpgradeableProxy} from "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {UpgradeableBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol";

import {Bootstrap} from "../src/core/Bootstrap.sol";
import {ClientChainGateway} from "../src/core/ClientChainGateway.sol";
import {CustomProxyAdmin} from "../src/core/CustomProxyAdmin.sol";
import {Vault} from "../src/core/Vault.sol";
import "../src/core/BeaconProxyBytecode.sol";
import "../src/core/ExoCapsule.sol";

import "forge-std/Script.sol";
import {BaseScript} from "./BaseScript.sol";
import {ILayerZeroEndpointV2} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";

contract DeployBootstrapOnly is BaseScript {
    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory prerequisiteContracts = vm.readFile("script/prerequisiteContracts.json");
        clientChainLzEndpoint = ILayerZeroEndpointV2(
            stdJson.readAddress(prerequisiteContracts, ".clientChain.lzEndpoint")
        );
        require(
            address(clientChainLzEndpoint) != address(0),
            "Client chain endpoint not found"
        );
        restakeToken = ERC20PresetFixedSupply(
            stdJson.readAddress(prerequisiteContracts, ".clientChain.erc20Token")
        );
        require(
            address(restakeToken) != address(0),
            "Restake token not found"
        );
        clientChain = vm.createSelectFork(clientChainRPCURL);
        // we should use the pre-requisite to save gas instead of deploying our own
        beaconOracle = EigenLayerBeaconOracle(
            stdJson.readAddress(prerequisiteContracts, ".clientChain.beaconOracle")
        );
        require(
            address(beaconOracle) != address(0),
            "Beacon oracle not found"
        );
        // same for BeaconProxyBytecode
        beaconProxyBytecode = BeaconProxyBytecode(
            stdJson.readAddress(prerequisiteContracts, ".clientChain.beaconProxyBytecode")
        );
        require(
            address(beaconProxyBytecode) != address(0),
            "Beacon proxy bytecode not found"
        );
    }

    function run() public {
        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        whitelistTokens.push(address(restakeToken));

        // proxy deployment
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        // vault, shared between bootstrap and client chain gateway
        vaultImplementation = new Vault();
        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        // bootstrap logic
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        // bootstrap implementation
        Bootstrap bootstrap = Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(Bootstrap.initialize,
                        (
                            exocoreValidatorSet.addr,
                            block.timestamp + 365 days + 24 hours,
                            24 hours,
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens, // vault is auto deployed
                            address(proxyAdmin)
                        )
                    )
                ))
            )
        );

        // initialize proxyAdmin with bootstrap address
        proxyAdmin.initialize(address(bootstrap));

        // now, focus on the client chain constructor
        capsuleImplementation = new ExoCapsule();
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));
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
        bytes memory initialization = abi.encodeWithSelector(
            clientGatewayLogic.initialize.selector,
            exocoreValidatorSet.addr,
            emptyList
        );
        bootstrap.setClientChainGatewayLogic(
            address(clientGatewayLogic),
            initialization
        );

        vm.stopBroadcast();

        string memory clientChainContracts = "clientChainContracts";
        vm.serializeAddress(clientChainContracts, "lzEndpoint", address(clientChainLzEndpoint));
        vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));
        vm.serializeAddress(clientChainContracts, "proxyAdmin", address(proxyAdmin));
        vm.serializeAddress(clientChainContracts, "vaultImplementation", address(vaultImplementation));
        vm.serializeAddress(clientChainContracts, "vaultBeacon", address(vaultBeacon));
        vm.serializeAddress(clientChainContracts, "beaconProxyBytecode", address(beaconProxyBytecode));
        vm.serializeAddress(clientChainContracts, "bootstrapLogic", address(bootstrapLogic));
        vm.serializeAddress(clientChainContracts, "bootstrap", address(bootstrap));
        vm.serializeAddress(clientChainContracts, "beaconOracle", address(beaconOracle));
        vm.serializeAddress(clientChainContracts, "capsuleImplementation", address(capsuleImplementation));
        vm.serializeAddress(clientChainContracts, "capsuleBeacon", address(capsuleBeacon));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "clientGatewayLogic", address(clientGatewayLogic));

        string memory deployedContracts = "deployedContracts";
        string memory finalJson =
            vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);

        vm.writeJson(finalJson, "script/deployedBootstrapOnly.json");
    }
}