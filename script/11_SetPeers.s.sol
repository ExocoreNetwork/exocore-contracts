pragma solidity ^0.8.19;

import {ExocoreGateway} from "../src/core/ExocoreGateway.sol";
import {Bootstrap} from "../src/core/Bootstrap.sol";

import {CLIENT_CHAINS_PRECOMPILE_ADDRESS} from "../src/interfaces/precompiles/IClientChains.sol";

import "forge-std/Script.sol";
import {BaseScript} from "./BaseScript.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";

contract SetPeersAndUpgrade is BaseScript {
    using AddressCast for address;

    address bootstrapAddr;
    address exocoreGatewayAddr;

    function setUp() public virtual override {
        // load keys
        super.setUp();
        // load contracts
        string memory deployed = vm.readFile("script/deployedBootstrapOnly.json");
        bootstrapAddr = stdJson.readAddress(deployed, ".clientChain.bootstrap");
        require(address(bootstrapAddr) != address(0), "bootstrap address should not be empty");
        deployed = vm.readFile("script/deployedExocoreGatewayOnly.json");
        exocoreGatewayAddr = stdJson.readAddress(deployed, ".exocore.exocoreGateway");
        require(address(exocoreGatewayAddr) != address(0), "exocore gateway address should not be empty");
        // forks
        exocore = vm.createSelectFork(exocoreRPCURL);
        clientChain = vm.createSelectFork(clientChainRPCURL);
    }

    function run() public {
        ExocoreGateway gateway = ExocoreGateway(payable(exocoreGatewayAddr));

        vm.selectFork(exocore);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        gateway.setPeer(clientChainId, bootstrapAddr.toBytes32());
        vm.stopBroadcast();

        Bootstrap bootstrap = Bootstrap(payable(bootstrapAddr));

        vm.selectFork(clientChain);
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        bootstrap.setPeer(exocoreChainId, address(exocoreGatewayAddr).toBytes32());
        vm.stopBroadcast();

        // check that peer is set (we run with --slow but even then there's some risk)
        uint256 i = 0;
        uint256 tries = 5;
        bool success;
        while (i < tries) {
            vm.selectFork(exocore);
            success = gateway.peers(clientChainId) == bootstrapAddr.toBytes32();

            vm.selectFork(clientChain);
            success = success && bootstrap.peers(exocoreChainId) == address(exocoreGatewayAddr).toBytes32();

            if (success) {
                break;
            }

            i++;
        }
        require(i < tries, "peers not set");

        // the upgrade does not work via script due to the precompile issue
        // https://github.com/ExocoreNetwork/exocore/issues/78
        // // now that peers are set, we should upgrade the Bootstrap contract via gateway
        // // but first allow simulation to run
        // vm.selectFork(exocore);
        // bytes memory mockCode = vm.getDeployedCode("ClientChainsMock.sol");
        // vm.etch(CLIENT_CHAINS_PRECOMPILE_ADDRESS, mockCode);

        // console.log("clientChainId", clientChainId);
        // vm.startBroadcast(exocoreValidatorSet.privateKey);
        // // fund the gateway
        // if (exocoreGatewayAddr.balance < 1 ether) {
        //     (bool sent,) = exocoreGatewayAddr.call{value: 1 ether}("");
        //     require(sent, "Failed to send Ether");
        // }
        // // gateway.markBootstrapOnAllChains();

        // instruct the user to upgrade manually
        // this can be done even without calling x/assets UpdateParams
        // because that parameter is not involved in this process.
        console.log("Cross-chain upgrade command:");
        console.log(
            "source .env && cast send --rpc-url $EXOCORE_TESETNET_RPC",
            exocoreGatewayAddr,
            '"markBootstrapOnAllChains()"',
            "--private-key $TEST_ACCOUNT_THREE_PRIVATE_KEY"
        );
    }
}
