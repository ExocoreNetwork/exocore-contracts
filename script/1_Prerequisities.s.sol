pragma solidity ^0.8.19;

import "./BaseScript.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

import "test/mocks/AssetsMock.sol";
import "test/mocks/ClaimRewardMock.sol";
import "test/mocks/DelegationMock.sol";
import {NonShortCircuitEndpointV2Mock} from "test/mocks/NonShortCircuitEndpointV2Mock.sol";

contract PrerequisitiesScript is BaseScript {

    function setUp() public virtual override {
        super.setUp();

        clientChain = vm.createSelectFork(clientChainRPCURL);

        // transfer some eth to deployer address
        exocore = vm.createSelectFork(exocoreRPCURL);
        _topUpPlayer(exocore, address(0), exocoreGenesis, deployer.addr, 1 ether);
    }

    function run() public {
        // deploy NonShortCircuitEndpointV2Mock first if USE_ENDPOINT_MOCK is true, otherwise use real endpoints.
        if (useEndpointMock) {
            vm.selectFork(clientChain);
            vm.startBroadcast(deployer.privateKey);
            clientChainLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet.addr);
            vm.stopBroadcast();

            vm.selectFork(exocore);
            vm.startBroadcast(deployer.privateKey);
            exocoreLzEndpoint = new NonShortCircuitEndpointV2Mock(exocoreChainId, exocoreValidatorSet.addr);
            vm.stopBroadcast();
        } else {
            clientChainLzEndpoint = ILayerZeroEndpointV2(sepoliaEndpointV2);
            exocoreLzEndpoint = ILayerZeroEndpointV2(exocoreEndpointV2);
        }

        if (useExocorePrecompileMock) {
            vm.selectFork(exocore);
            vm.startBroadcast(deployer.privateKey);
            assetsMock = address(new AssetsMock());
            delegationMock = address(new DelegationMock());
            claimRewardMock = address(new ClaimRewardMock());
            vm.stopBroadcast();
        }

        // use deployed ERC20 token as restake token
        restakeToken = ERC20PresetFixedSupply(erc20TokenAddress);

        string memory deployedContracts = "deployedContracts";
        string memory clientChainContracts = "clientChainContracts";
        string memory exocoreContracts = "exocoreContracts";
        vm.serializeAddress(clientChainContracts, "lzEndpoint", address(clientChainLzEndpoint));
        vm.serializeAddress(clientChainContracts, "beaconOracle", address(beaconOracle));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));

        if (useExocorePrecompileMock) {
            vm.serializeAddress(exocoreContracts, "assetsPrecompileMock", assetsMock);
            vm.serializeAddress(exocoreContracts, "delegationPrecompileMock", delegationMock);
            vm.serializeAddress(exocoreContracts, "claimRewardPrecompileMock", claimRewardMock);
        }

        string memory exocoreContractsOutput =
            vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));

        vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);

        vm.writeJson(finalJson, "script/prerequisiteContracts.json");
    }

}
