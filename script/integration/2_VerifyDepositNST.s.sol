// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

import "forge-std/StdJson.sol";
import "forge-std/console.sol";

import {Bootstrap} from "../../src/core/Bootstrap.sol";

import {BeaconOracle} from "./BeaconOracle.sol";
import {ALLOWED_CHAIN_ID} from "./NetworkConfig.sol";

import {BeaconChainProofs} from "src/libraries/BeaconChainProofs.sol";
import {Endian} from "src/libraries/Endian.sol";

contract VerifyDepositNST is Script {

    using Endian for bytes32;
    using stdJson for string;

    bytes32[] validatorContainer;
    BeaconChainProofs.ValidatorContainerProof validatorProof;
    bytes32 beaconBlockRoot;

    address bootstrapAddress;
    address beaconOracleAddress;
    uint256 nstDepositor;

    function setUp() public virtual {
        // vm.chainId(ALLOWED_CHAIN_ID);
        // obtain the address
        string memory deployments = vm.readFile("script/integration/deployments.json");
        bootstrapAddress = deployments.readAddress(".bootstrapAddress");
        require(bootstrapAddress != address(0), "Bootstrap address not found");
        beaconOracleAddress = deployments.readAddress(".beaconOracleAddress");
        require(beaconOracleAddress != address(0), "BeaconOracle address not found");
        nstDepositor =
            vm.envOr("NST_DEPOSITOR", uint256(0x47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd));
    }

    function run() external {
        vm.startBroadcast(nstDepositor);
        string memory data = vm.readFile("script/integration/proof.json");
        // load the validator container
        validatorContainer = data.readBytes32Array(".validatorContainer");
        // load the validator proof
        validatorProof = BeaconChainProofs.ValidatorContainerProof({
            stateRoot: data.readBytes32(".stateRoot"),
            stateRootProof: data.readBytes32Array(".stateRootProof"),
            validatorContainerRootProof: data.readBytes32Array(".validatorContainerProof"),
            validatorIndex: data.readUint(".validatorIndex"),
            beaconBlockTimestamp: data.readUint(".timestamp")
        });
        // since the oracle is not necessarily active during integration testing, trigger it manually
        BeaconOracle oracle = BeaconOracle(beaconOracleAddress);
        oracle.addTimestamp(validatorProof.beaconBlockTimestamp);
        // now, the transaction
        Bootstrap bootstrap = Bootstrap(bootstrapAddress);
        bootstrap.verifyAndDepositNativeStake(validatorContainer, validatorProof);
        vm.stopBroadcast();
    }

}
