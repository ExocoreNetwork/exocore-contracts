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
import "../test/mocks/NonShortCircuitLzEndpointMock.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";

contract DeployScript is Script {
    Player[] players;
    Player clientChainDeployer;
    Player exocoreValidatorSet;
    Player exocoreDeployer;

    string clientChainRPCURL;
    string exocoreRPCURL;

    address[] whitelistTokens;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway = ClientChainGateway(0xBC3f39Cf57921a49fFc3086237620217ed83A06e);
    Vault vault;
    ExocoreGateway exocoreGateway = ExocoreGateway(0x9c5D7272146Be2aA162142C89c2DF03B342B84BF);
    address clientChainLzEndpoint = 0x2a93D9e49C7072c2526FdD91D21574996243752e;
    address exocoreLzEndpoint = 0xa1E07f6a6a820019d326930a9a9F85f084FA774f;

    uint16 exocoreChainId = 10253; // LayerZero chainId
    uint16 clientChainId = 10161; // LayerZero chainId

    struct Player {
        uint256 privateKey;
        address addr;
    }
    
    function setUp() public {
        clientChainDeployer.privateKey = vm.envUint("ANVIL_DEPLOYER_PRIVATE_KEY");
        clientChainDeployer.addr = vm.addr(clientChainDeployer.privateKey);

        exocoreDeployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        exocoreDeployer.addr = vm.addr(exocoreDeployer.privateKey);
        
        exocoreValidatorSet.privateKey = vm.envUint("TEST_ACCOUNT_TWO_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);

        clientChainRPCURL = vm.envString("ETHEREUM_SEPOLIA_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");
    }

    function run() public {
        vm.createSelectFork(exocoreRPCURL);
        // setup Exocore testnet contracts state
        // Exocore validator set should be the owner of these contracts and only owner could setup contracts state
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        // set the destination endpoint for corresponding destinations in endpoint mock
        NonShortCircuitLzEndpointMock(exocoreLzEndpoint).setDestLzEndpoint(address(clientGateway), clientChainLzEndpoint);
        exocoreGateway.setTrustedRemote(clientChainId, abi.encodePacked(address(clientGateway), address(exocoreGateway)));
        vm.stopBroadcast();
    }
}
