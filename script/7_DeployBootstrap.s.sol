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

contract DeployBootstrapOnly is BaseScript {
    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory prerequisiteContracts = vm.readFile("script/prerequisiteContracts.json");
        clientChainLzEndpoint = ILayerZeroEndpointV2(
            stdJson.readAddress(prerequisiteContracts, ".clientChain.lzEndpoint")
        );
        restakeToken = ERC20PresetFixedSupply(
            stdJson.readAddress(prerequisiteContracts, ".clientChain.erc20Token")
        );
        clientChain = vm.createSelectFork(clientChainRPCURL);
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
        // proxy bytecode, also shared between the two
        beaconProxyBytecode = new BeaconProxyBytecode();
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
                            block.timestamp + 365 days,
                            24 hours,
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens, // vault is auto deployed
                            address(proxyAdmin)
                        )
                    )
                ))
            )
        );
        console.log("Bootstrap logic: ", address(bootstrapLogic));
        console.log("Bootstrap address: ", address(bootstrap));

        // now, focus on the client chain constructor
        beaconOracle = _deployBeaconOracle();
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
        console.log("Client chain gateway logic: ", address(clientGatewayLogic));

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