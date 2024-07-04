pragma solidity ^0.8.19;

import "../src/core/ClientChainGateway.sol";

import "../src/core/ExocoreGateway.sol";
import {Vault} from "../src/core/Vault.sol";

import "../src/storage/GatewayStorage.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

contract DeployScript is Script {

    Player[] players;
    Player depositor;
    Player clientChainDeployer;
    Player exocoreDeployer;
    Player relayer;
    Player exocoreValidatorSet;

    string clientChainRPCURL;
    string exocoreRPCURL;

    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    Vault vault;
    ExocoreGateway exocoreGateway;
    ILayerZeroEndpoint clientChainLzEndpoint;
    ILayerZeroEndpoint exocoreLzEndpoint;

    uint16 exocoreChainId = 0;
    uint16 clientChainId = 101;
    uint256 clientChain;
    uint256 exocore;
    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200_000;
    uint256 constant DEPOSIT_AMOUNT = 1e22;
    uint256 constant AIRDEOP_AMOUNT = 1e28;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    function setUp() public {
        clientChainDeployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        clientChainDeployer.addr = vm.addr(clientChainDeployer.privateKey);

        exocoreDeployer.privateKey = vm.envUint("TEST_ACCOUNT_TWO_PRIVATE_KEY");
        exocoreDeployer.addr = vm.addr(exocoreDeployer.privateKey);

        exocoreValidatorSet.privateKey = vm.envUint("TEST_ACCOUNT_THREE_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);

        depositor.privateKey = vm.envUint("TEST_ACCOUNT_FOUR_PRIVATE_KEY");
        depositor.addr = vm.addr(depositor.privateKey);

        relayer.privateKey = vm.envUint("TEST_ACCOUNT_FOUR_PRIVATE_KEY");
        relayer.addr = vm.addr(relayer.privateKey);

        clientChainRPCURL = vm.envString("SEPOLIA_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        clientGateway =
            ClientChainGateway(payable(stdJson.readAddress(deployedContracts, ".clientChain.clientChainGateway")));
        clientChainLzEndpoint = ILayerZeroEndpoint(stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint"));
        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(deployedContracts, ".clientChain.erc20Token"));
        vault = Vault(stdJson.readAddress(deployedContracts, ".clientChain.resVault"));

        exocoreGateway = ExocoreGateway(payable(stdJson.readAddress(deployedContracts, ".exocore.exocoreGateway")));
        exocoreLzEndpoint = ILayerZeroEndpoint(stdJson.readAddress(deployedContracts, ".exocore.lzEndpoint"));

        // transfer some gas fee to depositor, relayer and exocore gateway
        clientChain = vm.createSelectFork(clientChainRPCURL);
        address alexTest = 0x41B2ddC309Af448f0B96ba1595320D7Dc5121Bc0;
        address aduTest = 0x7Db30262Dbf13f464eb6126daFa7EB57623A7A01;
        address faucet = 0x8A21AE3e1344A83Bb05D5b1c9cFF04A9614F2567;
        // vm.startBroadcast(exocoreValidatorSet.privateKey);
        // if (restakeToken.balanceOf(faucet) < AIRDEOP_AMOUNT) {
        //     restakeToken.transfer(faucet, AIRDEOP_AMOUNT);
        // }
        // if (restakeToken.balanceOf(aduTest) < DEPOSIT_AMOUNT) {
        //     restakeToken.transfer(aduTest, DEPOSIT_AMOUNT);
        // }
        // if (restakeToken.balanceOf(clientChainDeployer.addr) < DEPOSIT_AMOUNT) {
        //     restakeToken.transfer(clientChainDeployer.addr, DEPOSIT_AMOUNT);
        // }
        // vm.stopBroadcast();

        vm.startBroadcast(clientChainDeployer.privateKey);
        if (address(clientGateway).balance < 0.2 ether) {
            (bool sent,) = address(clientGateway).call{value: 0.2 ether}("");
            require(sent, "Failed to send Ether");
        }
        if (exocoreValidatorSet.addr.balance < 0.02 ether) {
            (bool sent,) = exocoreValidatorSet.addr.call{value: 0.02 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreDeployer.privateKey);
        if (relayer.addr.balance < 1 ether) {
            (bool sent,) = relayer.addr.call{value: 0.1 ether}("");
            require(sent, "Failed to send Ether");
        }
        if (address(exocoreGateway).balance < 1 ether) {
            (bool sent,) = address(exocoreGateway).call{value: 0.1 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
    }

    function run() public {}

}
