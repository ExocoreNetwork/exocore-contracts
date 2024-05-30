pragma solidity ^0.8.19;

import {Bootstrap} from "../src/core/Bootstrap.sol";
import {Vault} from "../src/core/Vault.sol";
import {IOperatorRegistry} from "../src/interfaces/IOperatorRegistry.sol";

import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

import "forge-std/Script.sol";

// This script does not intentionally inherit from BaseScript, since
// that script has boilerplate that is not needed here.
contract RegisterOperatorsAndDelegate is Script {
    // registration data for operators
    uint256[] operatorKeys;
    string[] exoAddresses;
    string[] names;
    bytes32[] consKeys;
    // rpc settings
    string clientChainRPCURL;
    uint256 clientChain;
    // addresses of contracts
    address bootstrapAddr;
    address tokenAddr;
    // each subarray sums to deposits, and each item is the delegation amount
    uint256[4][4] amounts = [
        [ 1500 * 1e18, 250 * 1e18, 250 * 1e18, 0 * 1e18 ],
        [ 300 * 1e18, 1500 * 1e18, 0 * 1e18, 200 * 1e18 ],
        [ 0 * 1e18, 0 * 1e18, 2500 * 1e18, 500 * 1e18 ],
        [ 1000 * 1e18, 0 * 1e18, 0 * 1e18, 2000 * 1e18 ]
    ];
 
    function setUp() public {
        operatorKeys = vm.envUint("OPERATOR_KEYS", ",");
        exoAddresses = vm.envString("EXO_ADDRESSES", ",");
        names = vm.envString("NAMES", ",");
        consKeys = vm.envBytes32("CONS_KEYS", ",");

        clientChainRPCURL = vm.envString("SEPOLIA_RPC");
        clientChain = vm.createSelectFork(clientChainRPCURL);

        require(
            operatorKeys.length == exoAddresses.length &&
            operatorKeys.length == names.length &&
            operatorKeys.length == consKeys.length,
            "Operator registration data length mismatch"
        );

        string memory deployedContracts = vm.readFile("script/deployedBootstrapOnly.json");
        bootstrapAddr = stdJson.readAddress(deployedContracts, ".clientChain.bootstrap");
        require(bootstrapAddr != address(0), "Bootstrap address should not be empty");
        tokenAddr = stdJson.readAddress(deployedContracts, ".clientChain.erc20Token");
        require(tokenAddr != address(0), "Token address should not be empty");
    }

    function run() public {
        vm.selectFork(clientChain);
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        Bootstrap bootstrap = Bootstrap(bootstrapAddr);
        ERC20PresetFixedSupply token = ERC20PresetFixedSupply(tokenAddr);
        address vaultAddr = address(bootstrap.tokenToVault(tokenAddr));
        for(uint256 i = 0; i < operatorKeys.length; i++) {
            uint256 pk = operatorKeys[i];
            // address addr = vm.addr(pk);
            string memory exoAddr = exoAddresses[i];
            string memory name = names[i];
            bytes32 consKey = consKeys[i];
            vm.startBroadcast(pk);
            // register operator
            bootstrap.registerOperator(
                exoAddr, name, commission, consKey
            );
            uint256 depositAmount = 0;
            for(uint256 j = 0; j < amounts[i].length; j++) {
                depositAmount += amounts[i][j];
            }
            // approve
            token.approve(vaultAddr, type(uint256).max);
            // transfer
            bootstrap.deposit(tokenAddr, depositAmount);
            vm.stopBroadcast();
        }
        for(uint256 i = 0; i < operatorKeys.length; i++) {
            uint256 pk = operatorKeys[i];
            vm.startBroadcast(pk);
            for(uint256 j = 0; j < operatorKeys.length; j++) {
                uint256 amount = amounts[i][j];
                if (amount == 0) {
                    continue;
                }
                // i is the transaction sender and j is the operator
                string memory exoAddr = exoAddresses[j];
                bootstrap.delegateTo(exoAddr, tokenAddr, amount);
            }
            vm.stopBroadcast();
        }
    }
}