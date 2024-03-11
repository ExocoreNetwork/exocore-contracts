pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import {NonShortCircuitEndpointV2Mock} from "../test/mocks/NonShortCircuitEndpointV2Mock.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "./BaseScriptStorage.sol";

contract PrerequisitiesScript is Script, BaseScriptStorage {
    function setUp() public {
        deployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        deployer.addr = vm.addr(deployer.privateKey);

        exocoreValidatorSet.privateKey = vm.envUint("TEST_ACCOUNT_THREE_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);

        exocoreGenesis.privateKey = vm.envUint("EXOCORE_GENESIS_PRIVATE_KEY");
        exocoreGenesis.addr = vm.addr(exocoreGenesis.privateKey);

        clientChainRPCURL = vm.envString("SEPOLIA_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");

        clientChain = vm.createSelectFork(clientChainRPCURL);

        // transfer some eth to deployer address
        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreGenesis.privateKey);
        if (deployer.addr.balance < 1 ether) {
            (bool sent,) = deployer.addr.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
    }

    function run() public {
        // deploy NonShortCircuitEndpointV2Mock first if USE_ENDPOINT_MOCK is true, otherwise use real endpoints.
        if (vm.envBool("USE_ENDPOINT_MOCK")) {
            vm.selectFork(clientChain);
            vm.startBroadcast(deployer.privateKey);
            clientChainLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet.addr);
            vm.stopBroadcast();

            vm.selectFork(exocore);
            vm.startBroadcast(deployer.privateKey);
            exocoreLzEndpoint = new NonShortCircuitEndpointV2Mock(exocoreChainId, exocoreValidatorSet.addr);
            vm.stopBroadcast();
        } else {
            clientChainLzEndpoint = NonShortCircuitEndpointV2Mock(sepoliaEndpointV2);
            exocoreLzEndpoint = NonShortCircuitEndpointV2Mock(exocoreEndpointV2);
        }

        // use deployed ERC20 token as restake token
        restakeToken = ERC20PresetFixedSupply(erc20TokenAddress);

        string memory deployedContracts = "deployedContracts";
        string memory clientChainContracts = "clientChainContracts";
        string memory exocoreContracts = "exocoreContracts";
        vm.serializeAddress(clientChainContracts, "lzEndpoint", address(clientChainLzEndpoint));
        string memory clientChainContractsOutput =
            vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));

        string memory exocoreContractsOutput =
            vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));

        vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);

        vm.writeJson(finalJson, "script/prerequisitContracts.json");
    }
}
