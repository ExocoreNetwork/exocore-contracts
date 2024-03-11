pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import "../src/core/ExocoreGateway.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../src/interfaces/precompiles/IClaimReward.sol";
import "../src/storage/GatewayStorage.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "./BaseScriptStorage.sol";

contract DepositScript is Script, BaseScriptStorage {
    using AddressCast for address;

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
        require(address(clientGateway) != address(0), "clientGateway address should not be empty");

        clientChainLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "clientChainLzEndpoint address should not be empty");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(deployedContracts, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restakeToken address should not be empty");

        vault = Vault(stdJson.readAddress(deployedContracts, ".clientChain.resVault"));
        require(address(vault) != address(0), "vault address should not be empty");

        exocoreGateway = ExocoreGateway(payable(stdJson.readAddress(deployedContracts, ".exocore.exocoreGateway")));
        require(address(exocoreGateway) != address(0), "exocoreGateway address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocoreLzEndpoint address should not be empty");

        // bind precompile mock contracts code to constant precompile address so that local simulation could pass
        bytes memory DepositMockCode = vm.getDeployedCode("DepositMock.sol");
        vm.etch(DEPOSIT_PRECOMPILE_ADDRESS, DepositMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawPrincipleMockCode = vm.getDeployedCode("WithdrawPrincipleMock.sol");
        vm.etch(WITHDRAW_PRECOMPILE_ADDRESS, WithdrawPrincipleMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);

        // transfer some gas fee to depositor, relayer and exocore gateway
        clientChain = vm.createSelectFork(clientChainRPCURL);
        vm.startBroadcast(clientChainDeployer.privateKey);
        if (depositor.addr.balance < 0.2 ether) {
            (bool sent,) = depositor.addr.call{value: 0.2 ether}("");
            require(sent, "Failed to send Ether");
        }
        // if (address(clientGateway).balance < 0.02 ether) {
        //     (bool sent, ) = address(clientGateway).call{value: 0.02 ether}("");
        //     require(sent, "Failed to send Ether");
        // }
        if (exocoreValidatorSet.addr.balance < 0.02 ether) {
            (bool sent,) = exocoreValidatorSet.addr.call{value: 0.02 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();

        vm.startBroadcast(exocoreValidatorSet.privateKey);
        if (restakeToken.balanceOf(depositor.addr) < DEPOSIT_AMOUNT) {
            restakeToken.transfer(depositor.addr, DEPOSIT_AMOUNT);
        }
        vm.stopBroadcast();

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreDeployer.privateKey);
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
        restakeToken.approve(address(vault), type(uint256).max);
        clientGateway.deposit(address(restakeToken), DEPOSIT_AMOUNT);
        uint64 nonce = clientGateway.getOutboundNonce();
        vm.stopBroadcast();

        if (vm.envBool("USE_ENDPOINT_MOCK")) {
            vm.selectFork(exocore);
            vm.startBroadcast(relayer.privateKey);
            bytes memory payload = abi.encodePacked(
                GatewayStorage.Action.REQUEST_DEPOSIT,
                abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
                abi.encodePacked(bytes32(bytes20(depositor.addr))),
                uint256(DEPOSIT_AMOUNT)
            );
            exocoreLzEndpoint.lzReceive{gas: 500000}(
                Origin(clientChainId, address(clientGateway).toBytes32(), nonce),
                address(exocoreGateway),
                GUID.generate(
                    nonce, clientChainId, address(clientGateway), exocoreChainId, address(exocoreGateway).toBytes32()
                ),
                payload,
                bytes("")
            );
            vm.stopBroadcast();
        }
    }
}
