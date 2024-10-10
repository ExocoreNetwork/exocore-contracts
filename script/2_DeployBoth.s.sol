pragma solidity ^0.8.19;

import "../src/core/ClientChainGateway.sol";
import "../src/core/ExoCapsule.sol";
import "../src/core/ExocoreGateway.sol";

import {RewardVault} from "../src/core/RewardVault.sol";
import {Vault} from "../src/core/Vault.sol";
import "../src/utils/BeaconProxyBytecode.sol";
import "../src/utils/CustomProxyAdmin.sol";
import {ExocoreGatewayMock} from "../test/mocks/ExocoreGatewayMock.sol";

import {BaseScript} from "./BaseScript.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

contract DeployScript is BaseScript {

    function setUp() public virtual override {
        super.setUp();

        string memory prerequisities = vm.readFile("script/prerequisiteContracts.json");

        clientChainLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(prerequisities, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "client chain l0 endpoint should not be empty");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(prerequisities, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restake token address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(prerequisities, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocore l0 endpoint should not be empty");

        if (useExocorePrecompileMock) {
            assetsMock = stdJson.readAddress(prerequisities, ".exocore.assetsPrecompileMock");
            require(assetsMock != address(0), "assetsMock should not be empty");

            delegationMock = stdJson.readAddress(prerequisities, ".exocore.delegationPrecompileMock");
            require(delegationMock != address(0), "delegationMock should not be empty");

            rewardMock = stdJson.readAddress(prerequisities, ".exocore.rewardPrecompileMock");
            require(rewardMock != address(0), "rewardMock should not be empty");
        }

        clientChain = vm.createSelectFork(clientChainRPCURL);

        exocore = vm.createSelectFork(exocoreRPCURL);
        _topUpPlayer(exocore, address(0), exocoreGenesis, deployer.addr, 1 ether);
    }

    function run() public {
        // deploy clientchaingateway on client chain via rpc
        vm.selectFork(clientChain);
        vm.startBroadcast(deployer.privateKey);

        // deploy beacon chain oracle
        beaconOracle = _deployBeaconOracle();

        /// deploy vault implementation contract, capsule implementation contract, reward vault implementation contract
        /// that has logics called by proxy
        vaultImplementation = new Vault();
        capsuleImplementation = new ExoCapsule();
        rewardVaultImplementation = new RewardVault();

        /// deploy the vault beacon, capsule beacon, reward vault beacon that store the implementation contract address
        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));
        rewardVaultBeacon = new UpgradeableBeacon(address(rewardVaultImplementation));

        // deploy BeaconProxyBytecode to store BeaconProxyBytecode
        beaconProxyBytecode = new BeaconProxyBytecode();

        // deploy custom proxy admin
        clientChainProxyAdmin = new CustomProxyAdmin();

        /// deploy client chain gateway
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(beaconOracle),
            address(vaultBeacon),
            address(rewardVaultBeacon),
            address(capsuleBeacon),
            address(beaconProxyBytecode)
        );
        clientGateway = ClientChainGateway(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(clientGatewayLogic),
                        address(clientChainProxyAdmin),
                        abi.encodeWithSelector(
                            clientGatewayLogic.initialize.selector, payable(exocoreValidatorSet.addr)
                        )
                    )
                )
            )
        );

        // find vault according to uderlying token address
        vault = Vault(address(ClientChainGateway(payable(address(clientGateway))).tokenToVault(address(restakeToken))));

        vm.stopBroadcast();

        // deploy on Exocore via rpc
        vm.selectFork(exocore);
        vm.startBroadcast(deployer.privateKey);

        // deploy Exocore network contracts
        ProxyAdmin exocoreProxyAdmin = new ProxyAdmin();

        if (useExocorePrecompileMock) {
            ExocoreGatewayMock exocoreGatewayLogic =
                new ExocoreGatewayMock(address(exocoreLzEndpoint), assetsMock, rewardMock, delegationMock);
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
        vm.serializeAddress(clientChainContracts, "rewardVault", address(rewardVault));
        vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));
        vm.serializeAddress(clientChainContracts, "vaultBeacon", address(vaultBeacon));
        vm.serializeAddress(clientChainContracts, "rewardVaultBeacon", address(rewardVaultBeacon));
        vm.serializeAddress(clientChainContracts, "capsuleBeacon", address(capsuleBeacon));
        vm.serializeAddress(clientChainContracts, "beaconProxyBytecode", address(beaconProxyBytecode));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "proxyAdmin", address(clientChainProxyAdmin));

        vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));
        vm.serializeAddress(exocoreContracts, "exocoreGateway", address(exocoreGateway));

        if (useExocorePrecompileMock) {
            vm.serializeAddress(exocoreContracts, "assetsPrecompileMock", assetsMock);
            vm.serializeAddress(exocoreContracts, "delegationPrecompileMock", delegationMock);
            vm.serializeAddress(exocoreContracts, "rewardPrecompileMock", rewardMock);
        }

        string memory exocoreContractsOutput =
            vm.serializeAddress(exocoreContracts, "proxyAdmin", address(exocoreProxyAdmin));

        vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);

        vm.writeJson(finalJson, "script/deployedContracts.json");
    }

}
