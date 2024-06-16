pragma solidity ^0.8.19;

import "../src/interfaces/IClientChainGateway.sol";

import "../src/interfaces/IExocoreGateway.sol";
import "../src/interfaces/IVault.sol";
import {NonShortCircuitEndpointV2Mock} from "../test/mocks/NonShortCircuitEndpointV2Mock.sol";

import {BaseScript} from "./BaseScript.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

contract SetupScript is BaseScript {

    using AddressCast for address;

    function setUp() public virtual override {
        super.setUp();

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        clientGateway =
            IClientChainGateway(payable(stdJson.readAddress(deployedContracts, ".clientChain.clientChainGateway")));
        require(address(clientGateway) != address(0), "clientGateway address should not be empty");

        clientChainLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "clientChainLzEndpoint address should not be empty");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(deployedContracts, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restakeToken address should not be empty");

        vault = IVault(stdJson.readAddress(deployedContracts, ".clientChain.resVault"));
        require(address(vault) != address(0), "vault address should not be empty");

        exocoreGateway = IExocoreGateway(payable(stdJson.readAddress(deployedContracts, ".exocore.exocoreGateway")));
        require(address(exocoreGateway) != address(0), "exocoreGateway address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocoreLzEndpoint address should not be empty");

        // transfer some gas fee to exocore validator set address
        clientChain = vm.createSelectFork(clientChainRPCURL);
        _topUpPlayer(clientChain, address(0), deployer, exocoreValidatorSet.addr, 0.2 ether);

        exocore = vm.createSelectFork(exocoreRPCURL);
        _topUpPlayer(exocore, address(0), exocoreGenesis, exocoreValidatorSet.addr, 0.2 ether);
    }

    function run() public {
        // 1. setup client chain contracts to make them ready for sending and receiving messages from exocore gateway
        vm.selectFork(clientChain);
        // Exocore validator set should be the owner of these contracts and only owner could setup contracts state
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        // set the destination endpoint for corresponding destinations in endpoint mock if USE_ENDPOINT_MOCK is true
        if (useEndpointMock) {
            NonShortCircuitEndpointV2Mock(address(clientChainLzEndpoint)).setDestLzEndpoint(
                address(exocoreGateway), address(exocoreLzEndpoint)
            );
        }

        // as LzReceivers, gateway should set exocoreGateway as trusted remote to receive
        // messages
        clientGateway.setPeer(exocoreChainId, address(exocoreGateway).toBytes32());
        vm.stopBroadcast();

        // 2. setup Exocore testnet contracts to make them ready for sending and receiving messages from client chain
        // gateway
        vm.selectFork(exocore);
        // Exocore validator set should be the owner of these contracts and only owner could setup contracts state
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        // set the destination endpoint for corresponding destinations in endpoint mock if USE_ENDPOINT_MOCK is true
        if (useEndpointMock) {
            NonShortCircuitEndpointV2Mock(address(exocoreLzEndpoint)).setDestLzEndpoint(
                address(clientGateway), address(clientChainLzEndpoint)
            );
        }
        // this would also register clientChainId to Exocore native module
        exocoreGateway.setPeer(clientChainId, address(clientGateway).toBytes32());
        vm.stopBroadcast();

        // 3. we should register whitelist tokens to exocore
        vm.selectFork(clientChain);
        // Exocore validator set should be the owner of these contracts and only owner could add whitelist tokens
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        whitelistTokens.push(address(restakeToken));
        clientGateway.addWhitelistTokens(whitelistTokens);
        vm.stopBroadcast();
    }

}
