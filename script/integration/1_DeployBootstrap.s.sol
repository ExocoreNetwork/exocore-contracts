// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "forge-std/Script.sol";
import "../../src/core/Bootstrapping.sol";
import "../../src/core/MyToken.sol";

// Technically this is used for testing but it is marked as a script
// because it is a script that is used to deploy the contracts on Anvil
// and setup the initial state of the Exocore chain.

// The keys provided in the dot-env file are required to be already
// initialized by Anvil by `anvil --accounts 20`.
// When you run with this config, the keys already in the file will work
// because Anvil uses a common mnemonic across systems.
contract DeployContracts is Script {
    // assumes 3 operators, to add more - change registerOperators and delegate.
    uint256[] operators = vm.envUint("KEY_OPERATORS", ",");
    uint256[] stakers = vm.envUint("KEY_STAKERS", ",");
    Bootstrapping bootstrappingContract;
    // to add more tokens,
    // 0. add deployer private keys
    // 1. update the decimals
    // 2. increase the size of MyToken
    // 3. add information about tokens to deployTokens.
    // 4. update deposit and delegate amounts in fundAndApprove and delegate.
    // everywhere else we use the length of the myTokens array.
    uint256[] tokenDeployers = vm.envUint("KEY_TOKEN_DEPLOYERS", ",");
    uint8[2] decimals = [18, 6];
    MyToken[2] myTokens;

    function deployTokens() private {
        string[2] memory names = ["MyToken1", "MyToken2"];
        string[2] memory symbols = ["MT1", "MT2"];
        uint256[2] memory initialBalances = [
            2000 * 10 ** decimals[0], 5000 * 10 ** decimals[1]
        ];
        address[] memory initialAddresses = new address[](operators.length + stakers.length);
        for(uint256 i = 0; i < operators.length; i++) {
            initialAddresses[i] = vm.addr(operators[i]);
        }
        for(uint256 i = 0; i < stakers.length; i++) {
            initialAddresses[operators.length + i] = vm.addr(stakers[i]);
        }
        for(uint256 i = 0; i < tokenDeployers.length; i++) {
            vm.startBroadcast(tokenDeployers[i]);
            myTokens[i] = new MyToken(
                names[i], symbols[i], decimals[i], initialAddresses, initialBalances[i]
            );
            vm.stopBroadcast();
        }
    }

    function deployContract() private {
        uint256 contractDeployer = vm.envUint("KEY_DEPLOYER");
        address[] memory tokenAddressesForCall = new address[](myTokens.length);
        tokenAddressesForCall[0] = address(myTokens[0]);
        tokenAddressesForCall[1] = address(myTokens[1]);
        vm.startBroadcast(contractDeployer);
        bootstrappingContract = new Bootstrapping(
            tokenAddressesForCall, // supported tokens
            block.timestamp + 1 hours, // spawn time of Exocore chain
            30 minutes, // this much time before the spawn time, the contract freezes
            address(0x0) // TODO: set to the address which will mark bootstrapped
        );
        vm.stopBroadcast();
    }

    function fundAndApprove() private {
        // amounts deposited by each player, for the tokens 1 and 2.
        uint256[2] memory operatorAmounts = [1500 * 10 ** decimals[0], 2000 * 10 ** decimals[1]];
        // stakerAmounts - keep divisible by 3 for delegate
        uint256[2] memory stakerAmounts = [300 * 10 ** decimals[0], 600 * 10 ** decimals[1]];
        for(uint256 i = 0; i < myTokens.length; i++) {
            for(uint256 j = 0; j < operators.length; j++) {
                // this must be done at the beginning of each loop because the
                // broadcast changes to that of the operator.
                // vm.startBroadcast(tokenDeployers[i]);
                // myTokens[i].transfer(vm.addr(operators[j]), operatorAmounts[i]);
                // vm.stopBroadcast();
                vm.startBroadcast(operators[j]);
                myTokens[i].approve(address(bootstrappingContract), type(uint256).max);
                bootstrappingContract.deposit(address(myTokens[i]), operatorAmounts[i]);
                vm.stopBroadcast();
            }
        }
        for(uint256 i = 0; i < myTokens.length; i++) {
            for(uint256 j = 0; j < stakers.length; j++) {
                // vm.startBroadcast(tokenDeployers[i]);
                // myTokens[i].transfer(vm.addr(stakers[j]), stakerAmounts[i]);
                // vm.stopBroadcast();
                vm.startBroadcast(stakers[j]);
                myTokens[i].approve(address(bootstrappingContract), type(uint256).max);
                bootstrappingContract.deposit(address(myTokens[i]), stakerAmounts[i]);
                vm.stopBroadcast();
            }
        }
    }

    function registerOperators() private {
        // the mnemonics corresponding to the consensus public keys are given here. to recover,
        // echo "${MNEMONIC}" | exocored init localnet --chain-id exocorelocal_233-1 --recover
        // the value in this script is this one
        // exocored keys consensus-pubkey-to-bytes --output json | jq -r .bytes
        string[3] memory metaInfos = ["operator1", "operator2", "operator3"];
        bytes32[3] memory pubKeys = [
            // wonder quality resource ketchup occur stadium vicious output situate plug second
            // monkey harbor vanish then myself primary feed earth story real soccer shove like
            bytes32(0xF0F6919E522C5B97DB2C8255BFF743F9DFDDD7AD9FC37CB0C1670B480D0F9914),
            // carpet stem melt shove boring monster group hover afraid impulse give human
            // blanket notable repeat typical image menu know resist injury trick cancel robot
            bytes32(0x5CBB4508AD3F9C1D711314971211F991AC51B5EDDA2174866817D649E34EB691),
            // sugar vault poet soda excite puzzle news stool bonus harsh middle forget mosquito
            // wise sister language work muscle parade dad angry across emerge trade
            bytes32(0x4C9DE94E1F3225906602AE812E30F1BE56427126D60F2F6CB661B7F4FDA638DC)
        ];
        for (uint256 i = 0; i < operators.length; i++) {
            vm.startBroadcast(operators[i]);
            bootstrappingContract.registerOperator(
                pubKeys[i],
                vm.addr(operators[i]), // exocore address, which may be any address
                metaInfos[i]
            );
            vm.stopBroadcast();
        }
    }

    function delegate() private {
        // operator delegations. i used these values so that we have a mix of operators
        // delegating amongst themselves and to other operators. i also set it up such that
        // the amount for each self delegation is non zero, although that is not validated
        // in the contract.
        uint256[3][3][2] memory operatorDelegations = [
            [
                [200 * 10 ** decimals[0], 50 * 10 ** decimals[0], 50 * 10 ** decimals[0]],
                [0 * 10 ** decimals[0], 300 * 10 ** decimals[0], 0 * 10 ** decimals[0]],
                [100 * 10 ** decimals[0], 100 * 10 ** decimals[0], 100 * 10 ** decimals[0]]
            ],
            [
                [400 * 10 ** decimals[1], 200 * 10 ** decimals[1], 0 * 10 ** decimals[1]],
                [50 * 10 ** decimals[1], 550 * 10 ** decimals[1], 0 * 10 ** decimals[1]],
                [120 * 10 ** decimals[1], 80 * 10 ** decimals[1], 400 * 10 ** decimals[1]]
            ]
        ];
        for (uint256 i = 0; i < myTokens.length; i++) {
            MyToken myToken = myTokens[i];
            for (uint256 j = 0; j < operators.length; j++) {
                uint256 delegator = operators[j];
                for (uint256 k = 0; k < operators.length; k++) {
                    uint256 amount = operatorDelegations[i][j][k];
                    address operator = vm.addr(operators[k]);
                    vm.startBroadcast(delegator);
                    if (amount != 0) {
                        bootstrappingContract.delegateToOperator(
                            operator, address(myToken), amount
                        );
                    }
                    vm.stopBroadcast();
                }
            }
        }
        // now i have N stakers, with N operators and 2 tokens.
        // i will take 1/3 and 2/3 of the deposit amounts for each token for each staker
        // respectively
        // find a random number for those amounts for each operators
        // op1 = random1, op2 = random1, op3 = 1/3 - random1 - random2
        for (uint256 i = 0; i < myTokens.length; i++) {
            MyToken myToken = myTokens[i];
            for (uint256 j = 0; j < stakers.length; j++) {
                uint256 delegator = stakers[j];
                address delegatorAddress = vm.addr(delegator);
                (uint256 deposit, ) = bootstrappingContract.userDeposits(
                    delegatorAddress, address(myToken)
                );
                uint256 stakerDelegationToDo =  deposit * (i+1) / 3;
                for (uint256 k = 0; k < operators.length; k++) {
                    uint256 amount;
                    if (k == operators.length - 1) {
                        amount = stakerDelegationToDo;
                    } else {
                        amount = random(stakerDelegationToDo);
                    }
                    address operator = vm.addr(operators[k]);
                    vm.startBroadcast(delegator);
                    bootstrappingContract.delegateToOperator(
                        operator, address(myToken), amount
                    );
                    stakerDelegationToDo -= amount;
                    vm.stopBroadcast();
                }
            }
        }
    }

    function run() external {
        console.log("Starting");
        deployTokens();
        console.log("Tokens deployed");
        deployContract();
        console.log("Contract deployed");
        fundAndApprove();
        console.log("Funded and approved");
        registerOperators();
        console.log("Operators registered");
        delegate();
        console.log("Delegated; done!");

        for(uint256 i = 0; i < myTokens.length; i++) {
            console.log("Token ", i, " address: ", address(myTokens[i]));
            console.log("Deposits", bootstrappingContract.depositsByToken(address(myTokens[i])));
        }
    }

    // Helper function to generate a random number within a range
    function random(uint256 _range) internal view returns (uint256) {
        // Basic random number generation; consider a more robust approach for production
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % (_range - 1) + 1;
    }

}