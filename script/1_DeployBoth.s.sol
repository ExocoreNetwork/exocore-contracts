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
import "../src/mock/NonShortCircuitLzEndpointMock.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";

contract DeployScript is Script {
    Player[] players;
    Player clientChainExocoreValidatorSet;
    Player clientChaindeployer;
    Player exocoreValidatorSet;
    Player exocoredeployer;

    string clientChainRPCURL;
    string exocoreRPCURL;

    address[] whitelistTokens;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    Vault vault;
    ExocoreGateway exocoreGateway;
    ILayerZeroEndpoint clientChainLzEndpoint;
    ILayerZeroEndpoint exocoreLzEndpoint;

    uint16 exocoreChainId = 0;
    uint16 clientChainId = 1;

    struct Player {
        uint256 privateKey;
        address addr;
    }
    
    function setUp() public {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));

        clientChaindeployer.privateKey = vm.envUint("ANVIL_DEPLOYER_PRIVATE_KEY");
        clientChaindeployer.addr = vm.addr(clientChaindeployer.privateKey);
        clientChainExocoreValidatorSet.privateKey = vm.envUint("CLIENT_CHAIN_EXOCORE_VALIDATOR_SET_PRIVATE_KEY");
        clientChainExocoreValidatorSet.addr = vm.addr(clientChainExocoreValidatorSet.privateKey);

        exocoredeployer.privateKey = vm.envUint("EXOCORE_DEPLOYER_PRIVATE_KEY");
        exocoredeployer.addr = vm.addr(exocoredeployer.privateKey);
        
        exocoreValidatorSet.privateKey = vm.envUint("EXOCORE_VALIDATOR_SET_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);

        clientChainRPCURL = vm.envString("ETHEREUM_LOCAL_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_LOCAL_RPC");
    }

    function run() public {
        // deploy on client chain via rpc
        uint256 clientChain = vm.createSelectFork(clientChainRPCURL);

        vm.startBroadcast(clientChaindeployer.privateKey);
        restakeToken = new ERC20PresetFixedSupply(
            "rest",
            "rest",
            1e16,
            exocoreValidatorSet.addr
        );
        
        ProxyAdmin clientChainProxyAdmin = new ProxyAdmin();
        ClientChainGateway clientGatewayLogic = new ClientChainGateway();
        clientGateway = ClientChainGateway(address(new TransparentUpgradeableProxy(address(clientGatewayLogic), address(clientChainProxyAdmin), "")));
        Vault vaultLogic = new Vault();
        vault = Vault(address(new TransparentUpgradeableProxy(address(vaultLogic), address(clientChainProxyAdmin), "")));
        clientChainLzEndpoint = new NonShortCircuitLzEndpointMock(clientChainId);
        vm.stopBroadcast();

        // deploy on Exocore via rpc
        uint256 exocore = vm.createSelectFork(exocoreRPCURL);

        vm.startBroadcast(exocoredeployer.privateKey);
        ProxyAdmin exocoreProxyAdmin = new ProxyAdmin();
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway();
        exocoreGateway = ExocoreGateway(address(new TransparentUpgradeableProxy(address(exocoreGatewayLogic), address(exocoreProxyAdmin), "")));
        exocoreLzEndpoint = new NonShortCircuitLzEndpointMock(exocoreChainId);
        vm.stopBroadcast();

        // initialize exocore contracts
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        exocoreGateway.initialize(exocoreValidatorSet.addr, address(exocoreLzEndpoint));
        exocoreGateway.setTrustedRemote(clientChainId, abi.encodePacked(address(clientGateway), address(exocoreGateway)));
        NonShortCircuitLzEndpointMock(address(exocoreLzEndpoint)).setDestLzEndpoint(address(clientGateway), address(clientChainLzEndpoint));
        vm.stopBroadcast();

        vaults.push(address(vault));
        whitelistTokens.push(address(restakeToken));

        // switch back to client chain and initialize client chain contracts
        vm.selectFork(clientChain);

        vm.startBroadcast(clientChainExocoreValidatorSet.privateKey);
        clientGateway.initialize(payable(clientChainExocoreValidatorSet.addr), whitelistTokens, address(clientChainLzEndpoint), exocoreChainId);
        clientGateway.setTrustedRemote(exocoreChainId, abi.encodePacked(address(exocoreGateway), address(clientGateway)));
        vault.initialize(address(restakeToken), address(clientGateway));        
        NonShortCircuitLzEndpointMock(address(clientChainLzEndpoint)).setDestLzEndpoint(address(exocoreGateway), address(exocoreLzEndpoint));
        clientGateway.addTokenVaults(vaults);
        vm.stopBroadcast();

        string memory deployedContracts = "deployedContracts";
        string memory clientChainContracts = "clientChainContracts";
        string memory exocoreContracts = "exocoreContracts";
        vm.serializeAddress(clientChainContracts, "lzEndpoint", address(clientChainLzEndpoint));
        vm.serializeAddress(clientChainContracts, "clientChainGateway", address(clientGateway));
        vm.serializeAddress(clientChainContracts, "resVault", address(vault));
        vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));
        string memory clientChainContractsOutput = vm.serializeAddress(clientChainContracts, "proxyAdmin", address(clientChainProxyAdmin));

        vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));
        vm.serializeAddress(exocoreContracts, "exocoreGateway", address(exocoreGateway));
        string memory exocoreContractsOutput = vm.serializeAddress(exocoreContracts, "proxyAdmin", address(exocoreProxyAdmin));

        vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);
        
        vm.writeJson(finalJson, "script/deployedContracts.json");
    }
}
