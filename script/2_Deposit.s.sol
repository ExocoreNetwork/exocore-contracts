pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../src/interfaces/precompiles/IClaimReward.sol";
import "../test/mocks/NonShortCircuitLzEndpointMock.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import "../src/storage/GatewayStorage.sol";

contract DeployScript is Script {
    Player[] players;
    Player depositor;
    Player clientChainDeployer;
    Player exocoreDeployer;
    Player relayer;

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
    uint constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200000;

    struct Player {
        uint256 privateKey;
        address addr;
    }
    
    function setUp() public {
        clientChainDeployer.privateKey = vm.envUint("ANVIL_DEPLOYER_PRIVATE_KEY");
        clientChainDeployer.addr = vm.addr(clientChainDeployer.privateKey);

        exocoreDeployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        exocoreDeployer.addr = vm.addr(exocoreDeployer.privateKey);
        
        depositor.privateKey = vm.envUint("TEST_ACCOUNT_TWO_PRIVATE_KEY");
        depositor.addr = vm.addr(depositor.privateKey);

        relayer.privateKey = vm.envUint("TEST_ACCOUNT_THREE_PRIVATE_KEY");
        relayer.addr = vm.addr(relayer.privateKey);

        clientChainRPCURL = vm.envString("ETHEREUM_LOCAL_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        clientGateway = ClientChainGateway(stdJson.readAddress(deployedContracts, ".clientChain.clientChainGateway"));
        clientChainLzEndpoint = ILayerZeroEndpoint(stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint"));
        exocoreGateway = ExocoreGateway(payable(stdJson.readAddress(deployedContracts, ".exocore.exocoreGateway")));
        exocoreLzEndpoint = ILayerZeroEndpoint(stdJson.readAddress(deployedContracts, ".exocore.lzEndpoint"));

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
        if (depositor.addr.balance < 1 ether) {
            payable(depositor.addr).transfer(1 ether);
        }
        if (relayer.addr.balance < 1 ether) {
            payable(relayer.addr).transfer(1 ether);
        }
        vm.stopBroadcast();

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreDeployer.privateKey);
        if (depositor.addr.balance < 1 ether) {
            payable(depositor.addr).transfer(1 ether);
        }
        if (relayer.addr.balance < 1 ether) {
            payable(relayer.addr).transfer(1 ether);
        }
        if (address(exocoreGateway).balance < 1 ether) {
            address(exocoreGateway).call{value: 1 ether}("");
        }
        vm.stopBroadcast();
    }

    function run() public {
        vm.selectFork(exocore);
        vm.startBroadcast(relayer.privateKey);
        bytes memory payload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT, 
            abi.encodePacked(bytes32(bytes20(address(0xdAC17F958D2ee523a2206206994597C13D831ec7)))),
            abi.encodePacked(bytes32(bytes20(depositor.addr))),
            uint256(1234)
        );
        bytes memory path = abi.encodePacked(address(clientGateway), address(exocoreGateway));
        if (exocoreLzEndpoint.hasStoredPayload(clientChainId, path)) {
            exocoreLzEndpoint.forceResumeReceive(clientChainId, path);
        }
        uint64 nonce_ = exocoreLzEndpoint.getInboundNonce(clientChainId, path);
        exocoreLzEndpoint.receivePayload{gas: 500000}(
            clientChainId,
            path,
            address(exocoreGateway),
            nonce_+1,
            DEFAULT_ENDPOINT_CALL_GAS_LIMIT,
            payload
        );
        vm.stopBroadcast();
    }
}
