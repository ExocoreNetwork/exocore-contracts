pragma solidity ^0.8.19;

import {CombinedFaucet} from "../src/core/CombinedFaucet.sol";
import {BaseScript} from "./BaseScript.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import "forge-std/Script.sol";

contract DeployScript is BaseScript {

    address tokenAddr;
    bool exoEthFaucet;
    address faucetOwner;

    function setUp() public virtual override {
        super.setUp();

        string memory prerequisities = vm.readFile("script/prerequisiteContracts.json");

        tokenAddr = stdJson.readAddress(prerequisities, ".clientChain.erc20Token");
        require(tokenAddr != address(0), "restake token address should not be empty");

        clientChain = vm.createSelectFork(clientChainRPCURL);
        exocore = vm.createSelectFork(exocoreRPCURL);

        exoEthFaucet = vm.envBool("EXO_ETH_FAUCET");
        // for native token, using a different owner is better since the private key is exposed on the backend
        faucetOwner = vm.envAddress("FAUCET_OWNER");
    }

    function run() public {
        if (exoEthFaucet) {
            vm.selectFork(clientChain);
            vm.startBroadcast(exocoreValidatorSet.privateKey);
            address exoEthProxyAdmin = address(new ProxyAdmin());
            CombinedFaucet exoEthFaucetLogic = new CombinedFaucet();
            CombinedFaucet exoEthFaucet = CombinedFaucet(
                payable(
                    address(new TransparentUpgradeableProxy(address(exoEthFaucetLogic), address(exoEthProxyAdmin), ""))
                )
            );
            // give 1 exoETH per request
            exoEthFaucet.initialize(exocoreValidatorSet.addr, tokenAddr, 1 ether);
            vm.stopBroadcast();
            // do not store them as JSON since the address is intentionally kept private
            console.log("exoEthFaucet", address(exoEthFaucet));
            console.log("exoEthFaucetLogic", address(exoEthFaucetLogic));
            console.log("exoEthProxyAdmin", address(exoEthProxyAdmin));
        } else {
            vm.selectFork(exocore);
            vm.startBroadcast(exocoreValidatorSet.privateKey);
            address exoProxyAdmin = address(new ProxyAdmin());
            CombinedFaucet exoFaucetLogic = new CombinedFaucet();
            CombinedFaucet exoFaucet = CombinedFaucet(
                payable(address(new TransparentUpgradeableProxy(address(exoFaucetLogic), address(exoProxyAdmin), "")))
            );
            // give 1 exo per request
            exoFaucet.initialize(faucetOwner, address(0), 1 ether);
            vm.stopBroadcast();
            // do not store them as JSON since the address is intentionally kept private
            console.log("exoFaucet", address(exoFaucet));
            console.log("exoFaucetLogic", address(exoFaucetLogic));
            console.log("exoProxyAdmin", address(exoProxyAdmin));
        }
    }

}
