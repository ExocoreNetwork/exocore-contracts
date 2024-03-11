pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import {Vault} from "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "./BaseScriptStorage.sol";

contract DeployScript is Script, BaseScriptStorage {
    function setUp() public {
        clientChainDeployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        clientChainDeployer.addr = vm.addr(clientChainDeployer.privateKey);

        exocoreDeployer.privateKey = vm.envUint("TEST_ACCOUNT_TWO_PRIVATE_KEY");
        exocoreDeployer.addr = vm.addr(exocoreDeployer.privateKey);

        exocoreValidatorSet.privateKey = vm.envUint("TEST_ACCOUNT_THREE_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);

        exocoreGenesis.privateKey = vm.envUint("EXOCORE_GENESIS_PRIVATE_KEY");
        exocoreGenesis.addr = vm.addr(exocoreGenesis.privateKey);

        clientChainRPCURL = vm.envString("SEPOLIA_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");

        string memory deployedContracts = vm.readFile("script/prerequisitContracts.json");

        clientChainLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "client chain l0 endpoint should not be empty");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(deployedContracts, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restake token address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocore l0 endpoint should not be empty");

        clientChain = vm.createSelectFork(clientChainRPCURL);

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreGenesis.privateKey);
        if (exocoreDeployer.addr.balance < 1 ether) {
            (bool sent,) = exocoreDeployer.addr.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
    }

    function run() public {
        // deploy gateway and vault on client chain via rpc
        vm.selectFork(clientChain);
        vm.startBroadcast(clientChainDeployer.privateKey);
        ProxyAdmin clientChainProxyAdmin = new ProxyAdmin();
        whitelistTokens.push(address(restakeToken));
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(address(clientChainLzEndpoint));
        clientGateway = ClientChainGateway(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(clientGatewayLogic),
                        address(clientChainProxyAdmin),
                        abi.encodeWithSelector(
                            clientGatewayLogic.initialize.selector,
                            exocoreChainId,
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens
                        )
                    )
                )
            )
        );
        Vault vaultLogic = new Vault();
        vault = Vault(
            address(
                new TransparentUpgradeableProxy(
                    address(vaultLogic),
                    address(clientChainProxyAdmin),
                    abi.encodeWithSelector(
                        vaultLogic.initialize.selector, address(restakeToken), address(clientGateway)
                    )
                )
            )
        );
        vm.stopBroadcast();

        // deploy on Exocore via rpc
        vm.selectFork(exocore);
        vm.startBroadcast(exocoreDeployer.privateKey);
        // deploy Exocore network contracts
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

        string memory deployedContracts = "deployedContracts";
        string memory clientChainContracts = "clientChainContracts";
        string memory exocoreContracts = "exocoreContracts";
        vm.serializeAddress(clientChainContracts, "lzEndpoint", address(clientChainLzEndpoint));
        vm.serializeAddress(clientChainContracts, "clientChainGateway", address(clientGateway));
        vm.serializeAddress(clientChainContracts, "resVault", address(vault));
        vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "proxyAdmin", address(clientChainProxyAdmin));

        vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));
        vm.serializeAddress(exocoreContracts, "exocoreGateway", address(exocoreGateway));
        string memory exocoreContractsOutput =
            vm.serializeAddress(exocoreContracts, "proxyAdmin", address(exocoreProxyAdmin));

        vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);

        vm.writeJson(finalJson, "script/deployedContracts.json");
    }
}
