// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {EndpointV2Mock} from "../../test/mocks/EndpointV2Mock.sol";

import "../../src/core/BeaconProxyBytecode.sol";
import {Bootstrap} from "../../src/core/Bootstrap.sol";
import {CustomProxyAdmin} from "../../src/core/CustomProxyAdmin.sol";
import {Vault} from "../../src/core/Vault.sol";
import {IValidatorRegistry} from "../../src/interfaces/IValidatorRegistry.sol";
import {IVault} from "../../src/interfaces/IVault.sol";
import {MyToken} from "../../test/foundry/unit/MyToken.sol";

// Technically this is used for testing but it is marked as a script
// because it is a script that is used to deploy the contracts on Anvil
// and setup the initial state of the Exocore chain.

// The keys provided in the dot-env file are required to be already
// initialized by Anvil by `anvil --accounts 20`.
// When you run with this config, the keys already in the file will work
// because Anvil uses a common mnemonic across systems.
contract DeployContracts is Script {

    uint16 exocoreChainId = 1;
    uint16 clientChainId = 2;
    address exocoreValidatorSet = vm.addr(uint256(0x8));
    // assumes 3 validators, to add more - change registerValidators and delegate.
    uint256[] validators;
    uint256[] stakers;
    uint256 contractDeployer;
    Bootstrap bootstrap;
    // to add more tokens,
    // 0. add deployer private keys
    // 1. update the decimals
    // 2. increase the size of MyToken
    // 3. add information about tokens to deployTokens.
    // 4. update deposit and delegate amounts in fundAndApprove and delegate.
    // everywhere else we use the length of the myTokens array.
    uint256[] tokenDeployers;
    uint8[2] decimals = [18, 6];
    address[] whitelistTokens;
    Vault[] vaults;
    CustomProxyAdmin proxyAdmin;

    IVault vaultImplementation;
    IBeacon vaultBeacon;
    BeaconProxyBytecode beaconProxyBytecode;

    function setUp() private {
        // these are default values for Anvil's usual mnemonic.
        uint256[] memory ANVIL_VALIDATORS = new uint256[](3);
        ANVIL_VALIDATORS[0] = uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80);
        ANVIL_VALIDATORS[1] = uint256(0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d);
        ANVIL_VALIDATORS[2] = uint256(0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a);

        uint256[] memory ANVIL_STAKERS = new uint256[](7);
        ANVIL_STAKERS[0] = uint256(0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6);
        ANVIL_STAKERS[1] = uint256(0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a);
        ANVIL_STAKERS[2] = uint256(0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba);
        ANVIL_STAKERS[3] = uint256(0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e);
        ANVIL_STAKERS[4] = uint256(0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356);
        ANVIL_STAKERS[5] = uint256(0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97);
        ANVIL_STAKERS[6] = uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6);

        uint256[] memory ANVIL_TOKEN_DEPLOYERS = new uint256[](2);
        ANVIL_TOKEN_DEPLOYERS[0] = uint256(0x701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82);
        ANVIL_TOKEN_DEPLOYERS[1] = uint256(0xa267530f49f8280200edf313ee7af6b827f2a8bce2897751d06a843f644967b1);

        uint256 CONTRACT_DEPLOYER = uint256(0xf214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897);

        validators = vm.envOr("ANVIL_VALIDATORS", ",", ANVIL_VALIDATORS);
        stakers = vm.envOr("ANVIL_STAKERS", ",", ANVIL_STAKERS);
        tokenDeployers = vm.envOr("ANVIL_TOKEN_DEPLOYERS", ",", ANVIL_TOKEN_DEPLOYERS);
        contractDeployer = vm.envOr("CONTRACT_DEPLOYER", CONTRACT_DEPLOYER);
    }

    function deployTokens() private {
        string[2] memory names = ["MyToken1", "MyToken2"];
        string[2] memory symbols = ["MT1", "MT2"];
        uint256[2] memory initialBalances = [2000 * 10 ** decimals[0], 5000 * 10 ** decimals[1]];
        address[] memory initialAddresses = new address[](validators.length + stakers.length);
        for (uint256 i = 0; i < validators.length; i++) {
            initialAddresses[i] = vm.addr(validators[i]);
        }
        for (uint256 i = 0; i < stakers.length; i++) {
            initialAddresses[validators.length + i] = vm.addr(stakers[i]);
        }
        for (uint256 i = 0; i < tokenDeployers.length; i++) {
            vm.startBroadcast(tokenDeployers[i]);
            MyToken myToken = new MyToken(names[i], symbols[i], decimals[i], initialAddresses, initialBalances[i]);
            whitelistTokens.push(address(myToken));
            vm.stopBroadcast();
        }
    }

    function deployContract() private {
        vm.startBroadcast(contractDeployer);

        /// deploy vault implementationcontract that has logics called by proxy
        vaultImplementation = new Vault();

        /// deploy the vault beacon that store the implementation contract address
        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));

        // deploy BeaconProxyBytecode to store BeaconProxyBytecode
        beaconProxyBytecode = new BeaconProxyBytecode();

        proxyAdmin = new CustomProxyAdmin();
        EndpointV2Mock clientChainLzEndpoint = new EndpointV2Mock(clientChainId);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint), exocoreChainId, address(vaultBeacon), address(beaconProxyBytecode)
        );
        bootstrap = Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (
                                vm.addr(contractDeployer),
                                block.timestamp + 3 minutes,
                                1 seconds,
                                payable(exocoreValidatorSet),
                                whitelistTokens,
                                address(proxyAdmin)
                            )
                        )
                    )
                )
            )
        );
        vm.stopBroadcast();
        console.log("Bootstrap address: ", address(bootstrap));
    }

    function approveAndDeposit() private {
        // amounts deposited by each validators, for the tokens 1 and 2.
        uint256[2] memory validatorAmounts = [1500 * 10 ** decimals[0], 2000 * 10 ** decimals[1]];
        // stakerAmounts - keep divisible by 3 for delegate
        uint256[2] memory stakerAmounts = [300 * 10 ** decimals[0], 600 * 10 ** decimals[1]];
        for (uint256 i = 0; i < whitelistTokens.length; i++) {
            for (uint256 j = 0; j < validators.length; j++) {
                vm.startBroadcast(validators[j]);
                MyToken(whitelistTokens[i]).approve(address(vaults[i]), type(uint256).max);
                bootstrap.deposit(whitelistTokens[i], validatorAmounts[i]);
                vm.stopBroadcast();
            }
        }
        for (uint256 i = 0; i < whitelistTokens.length; i++) {
            for (uint256 j = 0; j < stakers.length; j++) {
                vm.startBroadcast(stakers[j]);
                MyToken(whitelistTokens[i]).approve(address(vaults[i]), type(uint256).max);
                bootstrap.deposit(whitelistTokens[i], stakerAmounts[i]);
                vm.stopBroadcast();
            }
        }
    }

    function registerValidators() private {
        // the mnemonics corresponding to the consensus public keys are given here. to recover,
        // echo "${MNEMONIC}" | exocored init localnet --chain-id exocorelocal_233-1 --recover
        // the value in this script is this one
        // exocored keys consensus-pubkey-to-bytes --output json | jq -r .bytes
        string[3] memory exos = [
            // these addresses will accrue rewards but they are not needed to keep the chain
            // running.
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac",
            "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2",
            "exo1rtg0cgw94ep744epyvanc0wdd5kedwql73vlmr"
        ];
        string[3] memory names = ["validator1", "validator2", "validator3"];
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
        IValidatorRegistry.Commission memory commission = IValidatorRegistry.Commission(0, 1e18, 1e18);
        for (uint256 i = 0; i < validators.length; i++) {
            vm.startBroadcast(validators[i]);
            bootstrap.registerValidator(exos[i], names[i], commission, pubKeys[i]);
            vm.stopBroadcast();
        }
    }

    function delegate() private {
        // validator delegations. i used these values so that we have a mix of validators
        // delegating amongst themselves and to other validators. i also set it up such that
        // the amount for each self delegation is non zero, although that is not validated
        // in the contract.
        uint256[3][3][2] memory validatorDelegations = [
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
        for (uint256 i = 0; i < whitelistTokens.length; i++) {
            for (uint256 j = 0; j < validators.length; j++) {
                uint256 delegator = validators[j];
                for (uint256 k = 0; k < validators.length; k++) {
                    uint256 amount = validatorDelegations[i][j][k];
                    address validator = vm.addr(validators[k]);
                    string memory validatorExo = bootstrap.ethToExocoreAddress(validator);
                    vm.startBroadcast(delegator);
                    if (amount != 0) {
                        bootstrap.delegateTo(validatorExo, whitelistTokens[i], amount);
                    }
                    vm.stopBroadcast();
                }
            }
        }
        // now i have N stakers, with N validators and 2 tokens.
        // i will take 1/3 and 2/3 of the deposit amounts for each token for each staker
        // respectively
        // find a random number for those amounts for each validators
        // op1 = random1, op2 = random2, op3 = 1/3 - random1 - random2
        for (uint256 i = 0; i < whitelistTokens.length; i++) {
            for (uint256 j = 0; j < stakers.length; j++) {
                uint256 delegator = stakers[j];
                address delegatorAddress = vm.addr(delegator);
                uint256 deposit = bootstrap.totalDepositAmounts(delegatorAddress, whitelistTokens[i]);
                uint256 stakerDelegationToDo = (deposit * (i + 1)) / 3;
                for (uint256 k = 0; k < validators.length; k++) {
                    uint256 amount;
                    if (k == validators.length - 1) {
                        amount = stakerDelegationToDo;
                    } else {
                        amount = random(stakerDelegationToDo);
                    }
                    address validator = vm.addr(validators[k]);
                    string memory exo = bootstrap.ethToExocoreAddress(validator);
                    vm.startBroadcast(delegator);
                    bootstrap.delegateTo(exo, whitelistTokens[i], amount);
                    stakerDelegationToDo -= amount;
                    vm.stopBroadcast();
                }
            }
        }
    }

    function run() external {
        console.log("Loading keys and addresses");
        setUp();
        console.log("Set up complete");
        deployTokens();
        console.log("Tokens deployed");
        deployContract();
        console.log("Contract deployed");
        approveAndDeposit();
        console.log("Approved and deposited");
        registerValidators();
        console.log("Validators registered");
        delegate();
        console.log("[Delegated]; done!");

        for (uint256 i = 0; i < whitelistTokens.length; i++) {
            console.log("Token ", i, " address: ", whitelistTokens[i]);
        }
    }

    // Helper function to generate a random number within a range
    function random(uint256 _range) internal view returns (uint256) {
        // Basic random number generation; consider a more robust approach for production
        return (uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % (_range - 1)) + 1;
    }

}
