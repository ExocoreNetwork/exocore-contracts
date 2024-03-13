pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import {Vault} from "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "../test/mocks/ExocoreGatewayMock.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {BaseScript} from "./BaseScript.sol";

contract DeployScript is BaseScript {
    function setUp() public virtual override {
        super.setUp();

        string memory deployedContracts = vm.readFile("script/prerequisitContracts.json");

        clientChainLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "client chain l0 endpoint should not be empty");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(deployedContracts, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restake token address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocore l0 endpoint should not be empty");

        if (useExocorePrecompileMock) {
            depositMock = stdJson.readAddress(deployedContracts, ".exocore.depositPrecompileMock");
            require(depositMock != address(0), "depositMock should not be empty");

            withdrawMock = stdJson.readAddress(deployedContracts, ".exocore.withdrawPrecompileMock");
            require(withdrawMock != address(0), "withdrawMock should not be empty");

            delegationMock = stdJson.readAddress(deployedContracts, ".exocore.delegationPrecompileMock");
            require(delegationMock != address(0), "delegationMock should not be empty");

            claimRewardMock = stdJson.readAddress(deployedContracts, ".exocore.claimRewardPrecompileMock");
            require(claimRewardMock != address(0), "claimRewardMock should not be empty");
        }

        clientChain = vm.createSelectFork(clientChainRPCURL);

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreGenesis.privateKey);
        if (deployer.addr.balance < 1 ether) {
            (bool sent,) = deployer.addr.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
    }

    function run() public {
        // deploy gateway and vault on client chain via rpc
        vm.selectFork(clientChain);
        vm.startBroadcast(deployer.privateKey);
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
        vm.startBroadcast(deployer.privateKey);
        // deploy Exocore network contracts
        ProxyAdmin exocoreProxyAdmin = new ProxyAdmin();

        if (useExocorePrecompileMock) {
            ExocoreGatewayMock exocoreGatewayLogic = new ExocoreGatewayMock(
                address(exocoreLzEndpoint),
                depositMock,
                withdrawMock,
                delegationMock,
                claimRewardMock
            );
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
        } else {
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
        }

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

        if (useExocorePrecompileMock) {
            vm.serializeAddress(exocoreContracts, "depositPrecompileMock", depositMock);
            vm.serializeAddress(exocoreContracts, "withdrawPrecompileMock", withdrawMock);
            vm.serializeAddress(exocoreContracts, "delegationPrecompileMock", delegationMock);
            vm.serializeAddress(exocoreContracts, "claimRewardPrecompileMock", claimRewardMock);
        }
        
        string memory exocoreContractsOutput =
            vm.serializeAddress(exocoreContracts, "proxyAdmin", address(exocoreProxyAdmin));

        vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);

        vm.writeJson(finalJson, "script/deployedContracts.json");
    }
}
