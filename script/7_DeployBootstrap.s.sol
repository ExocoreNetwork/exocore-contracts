pragma solidity ^0.8.19;

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {Bootstrap} from "../src/core/Bootstrap.sol";
import {ClientChainGateway} from "../src/core/ClientChainGateway.sol";

import "../src/core/ExoCapsule.sol";
import {Vault} from "../src/core/Vault.sol";
import "../src/utils/BeaconProxyBytecode.sol";
import {CustomProxyAdmin} from "../src/utils/CustomProxyAdmin.sol";

import {BaseScript} from "./BaseScript.sol";
import {ILayerZeroEndpointV2} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";

contract DeployBootstrapOnly is BaseScript {

    address wstETH;

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
    }

    function run() public {
        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        whitelistTokens.push(address(restakeToken));
        tvlLimits.push(restakeToken.totalSupply() / 20);
        whitelistTokens.push(wstETH);
        // doesn't matter if it's actually ERC20PresetFixedSupply, just need the total supply
        tvlLimits.push(ERC20PresetFixedSupply(wstETH).totalSupply() / 20);

        // proxy deployment
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        // vault, shared between bootstrap and client chain gateway
        vaultImplementation = new Vault();
        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        // bootstrap logic
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint), exocoreChainId, address(vaultBeacon), address(beaconProxyBytecode)
        );
        // client chain constructor (upgrade details)
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
        bytes memory initialization =
            abi.encodeWithSelector(clientGatewayLogic.initialize.selector, exocoreValidatorSet.addr, emptyList);
        // bootstrap implementation
        Bootstrap bootstrap = Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            Bootstrap.initialize,
                            (
                                exocoreValidatorSet.addr,
                                // 1 week from now
                                block.timestamp + 168 hours,
                                2 seconds,
                                whitelistTokens, // vault is auto deployed
                                tvlLimits,
                                address(proxyAdmin),
                                address(clientGatewayLogic),
                                initialization
                            )
                        )
                    )
                )
            )
        );

        // initialize proxyAdmin with bootstrap address
        proxyAdmin.initialize(address(bootstrap));

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
        vm.serializeAddress(clientChainContracts, "beaconOracle", address(beaconOracle));
        vm.serializeAddress(clientChainContracts, "capsuleImplementation", address(capsuleImplementation));
        vm.serializeAddress(clientChainContracts, "capsuleBeacon", address(capsuleBeacon));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "clientGatewayLogic", address(clientGatewayLogic));

        string memory deployedContracts = "deployedContracts";
        string memory finalJson = vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);

        vm.writeJson(finalJson, "script/deployedBootstrapOnly.json");
    }

}
