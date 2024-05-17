pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/interfaces/IClientChainGateway.sol";
import "../src/interfaces/IVault.sol";
import "../src/interfaces/IExocoreGateway.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../src/interfaces/precompiles/IClaimReward.sol";
import "../src/storage/GatewayStorage.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import {BaseScript} from "./BaseScript.sol";
import "forge-std/StdJson.sol";

contract DepositScript is BaseScript {
    using AddressCast for address;

    function setUp() public virtual override {
        super.setUp();

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        clientGateway =
            IClientChainGateway(payable(stdJson.readAddress(deployedContracts, ".clientChain.clientChainGateway")));
        require(address(clientGateway) != address(0), "clientGateway address should not be empty");

        if (!useExocorePrecompileMock) {
            // bind precompile mock contracts code to constant precompile address so that local simulation could pass
            bytes memory DepositMockCode = vm.getDeployedCode("DepositWithdrawMock.sol");
            vm.etch(DEPOSIT_PRECOMPILE_ADDRESS, DepositMockCode);

            bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
            vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

            bytes memory WithdrawPrincipleMockCode = vm.getDeployedCode("DepositWithdrawMock.sol");
            vm.etch(WITHDRAW_PRECOMPILE_ADDRESS, WithdrawPrincipleMockCode);

            bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
            vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);
        }

        // transfer some gas fee to depositor, relayer and exocore gateway
        clientChain = vm.createSelectFork(clientChainRPCURL);
        vm.startBroadcast(deployer.privateKey);
        if (depositor.addr.balance < 0.2 ether) {
            (bool sent,) = depositor.addr.call{value: 0.2 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreGenesis.privateKey);
        if (depositor.addr.balance < 2 ether) {
            (bool sent,) = depositor.addr.call{value: 2 ether}("");
            require(sent, "Failed to send Ether");
        }
        if (relayer.addr.balance < 2 ether) {
            (bool sent,) = relayer.addr.call{value: 2 ether}("");
            require(sent, "Failed to send Ether");
        }
        if (address(exocoreGateway).balance < 2 ether) {
            (bool sent,) = address(exocoreGateway).call{value: 2 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
    }

    function run() public {
        vm.selectFork(clientChain);
        vm.startBroadcast(depositor.privateKey);

        address capsule = clientGateway.createExoCapsule();

        vm.stopBroadcast();

        string memory capsulesJson = "capsule1";
        vm.serializeAddress(capsulesJson, "owner", depositor.addr);
        string memory capsulesOutput = vm.serializeAddress(capsulesJson, "capsule", capsule);

        vm.writeJson(capsulesOutput, "script/capsule.json");
    }
}
