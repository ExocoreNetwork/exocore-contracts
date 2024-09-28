pragma solidity ^0.8.19;

import {Bootstrap} from "../src/core/Bootstrap.sol";
import {ExocoreGateway} from "../src/core/ExocoreGateway.sol";
import {Action, GatewayStorage} from "../src/storage/GatewayStorage.sol";

import {BaseScript} from "./BaseScript.sol";
import "forge-std/Script.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";

contract AddToken is BaseScript {

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

        bytes32 token = hex"d457b91ba64d7d6653b50e5ca92508d8e09f4d28315a8d9d65694c5c80455534";
        uint256 tvlLimit = 50000000000000000;
        string memory name = "Jito2";
        string memory metaData = "Jito2 on solana";
        string memory oracleInfo = "LINK,Solana";

        addWhiteListToken(40168, token, 9, tvlLimit, name, metaData, oracleInfo);

    }

    function addWhiteListToken(uint32 clientchainId, bytes32 token, uint8 decimals, uint256 tvlLimit, string memory name, string memory metaData, string memory oracleInfo) private {
        vm.selectFork(exocore);
        vm.startBroadcast(depositor.privateKey);
        bytes memory msg_ = abi.encodePacked(
            GatewayStorage.Action.REQUEST_ADD_WHITELIST_TOKEN,
            abi.encodePacked(token) // convert for decoding it on the receiving end
        );
        uint256 nativeFee = exocoreGateway.quote(clientchainId, msg_);
        console.log("fee is: ", nativeFee);
        console.log("clientchainId is: ", clientchainId);
        ExocoreGateway(payable(address(exocoreGateway))).addWhitelistToken{value: nativeFee}(clientchainId, token, decimals, tvlLimit, name, metaData, oracleInfo);
        vm.stopBroadcast();
    }


}
