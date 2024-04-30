pragma solidity ^0.8.19;

import "../src/core/ClientChainGateway.sol";
import {Vault} from "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "../test/mocks/ExocoreGatewayMock.sol";
import "../src/core/ExoCapsule.sol";

import "forge-std/Script.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {UpgradeableBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import {BaseScript} from "./BaseScript.sol";

contract DeployScript is BaseScript {
    function setUp() public virtual override {
        super.setUp();

        string memory prerequisities = vm.readFile("script/prerequisitContracts.json");

        clientChainLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(prerequisities, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "client chain l0 endpoint should not be empty");

        beaconOracle = IBeaconChainOracle(stdJson.readAddress(prerequisities, ".clientChain.beaconOracle"));
        require(address(beaconOracle) != address(0), "client chain beacon oracle should not be empty");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(prerequisities, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restake token address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(prerequisities, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocore l0 endpoint should not be empty");

        if (useExocorePrecompileMock) {
            depositMock = stdJson.readAddress(prerequisities, ".exocore.depositPrecompileMock");
            require(depositMock != address(0), "depositMock should not be empty");

            withdrawMock = stdJson.readAddress(prerequisities, ".exocore.withdrawPrecompileMock");
            require(withdrawMock != address(0), "withdrawMock should not be empty");

            delegationMock = stdJson.readAddress(prerequisities, ".exocore.delegationPrecompileMock");
            require(delegationMock != address(0), "delegationMock should not be empty");

            claimRewardMock = stdJson.readAddress(prerequisities, ".exocore.claimRewardPrecompileMock");
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
        // deploy clientchaingateway on client chain via rpc
        vm.selectFork(clientChain);
        vm.startBroadcast(deployer.privateKey);
        
        /// deploy vault implementation contract and capsule implementation contract
        /// that has logics called by proxy
        vaultImplementation = new Vault();
        capsuleImplementation = new ExoCapsule();

        /// deploy the vault beacon and capsule beacon that store the implementation contract address
        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));

        /// deploy client chain gateway
        whitelistTokens.push(address(restakeToken));

        ProxyAdmin clientChainProxyAdmin = new ProxyAdmin();
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(beaconOracle),
            address(vaultBeacon),
            address(capsuleBeacon)
        );
        clientGateway = ClientChainGateway(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(clientGatewayLogic),
                        address(clientChainProxyAdmin),
                        abi.encodeWithSelector(
                            clientGatewayLogic.initialize.selector,
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens
                        )
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
                address(exocoreLzEndpoint), depositMock, withdrawMock, delegationMock, claimRewardMock
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
        vm.serializeAddress(clientChainContracts, "beaconOracle", address(beaconOracle));
        vm.serializeAddress(clientChainContracts, "clientChainGateway", address(clientGateway));
        vm.serializeAddress(clientChainContracts, "resVault", address(vault));
        vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));
        vm.serializeAddress(clientChainContracts, "vaultBeacon", address(vaultBeacon));
        vm.serializeAddress(clientChainContracts, "capsuleBeacon", address(capsuleBeacon));
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
