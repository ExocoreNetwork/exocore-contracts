pragma solidity ^0.8.19;

import {TransparentUpgradeableProxy} from "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {Bootstrap} from "../src/core/Bootstrap.sol";
import {ClientChainGateway} from "../src/core/ClientChainGateway.sol";
import {CustomProxyAdmin} from "../src/core/CustomProxyAdmin.sol";
import {Vault} from "../src/core/Vault.sol";

import "forge-std/Script.sol";
import {BaseScript} from "./BaseScript.sol";
import {ILayerZeroEndpointV2} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

contract DeployBootstrapOnly is BaseScript {
    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory deployedContracts = vm.readFile("script/prerequisitContracts.json");
        clientChainLzEndpoint = ILayerZeroEndpointV2(
            stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint")
        );
        restakeToken = ERC20PresetFixedSupply(
            stdJson.readAddress(deployedContracts, ".clientChain.erc20Token")
        );
        clientChain = vm.createSelectFork(clientChainRPCURL);

        // can't reuse the vault.
    }

    function run() public {
        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        whitelistTokens.push(address(restakeToken));
        // proxy deployment
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        // bootstrap logic
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
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
                            exocoreChainId,
                            // _exocoreValidatorSetAddress
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens,
                            address(proxyAdmin)
                        )
                    )
                ))
            )
        );
        console.log("Bootstrap logic: ", address(bootstrapLogic));
        console.log("Bootstrap address: ", address(bootstrap));

        Vault vaultLogic = new Vault();
        Vault vault = Vault(address(new TransparentUpgradeableProxy(
            address(vaultLogic), address(proxyAdmin), ""
        )));
        vault.initialize(address(restakeToken), address(bootstrap));
        address[] memory vaultAddresses = new address[](1);
        vaultAddresses[0] = address(vault);
        bootstrap.addTokenVaults(vaultAddresses);

        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint)
        );
        bytes memory initialization = abi.encodeWithSelector(
            clientGatewayLogic.initialize.selector,
            exocoreChainId,
            payable(exocoreValidatorSet.addr),
            whitelistTokens
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
        vm.serializeAddress(clientChainContracts, "bootstrapLogic", address(bootstrapLogic));
        vm.serializeAddress(clientChainContracts, "bootstrap", address(bootstrap));
        vm.serializeAddress(clientChainContracts, "resVault", address(vault));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "clientGatewayLogic", address(clientGatewayLogic));

        string memory deployedContracts = "deployedContracts";
        string memory finalJson =
            vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);

        vm.writeJson(finalJson, "script/deployedBootstrapOnly.json");
    }
}