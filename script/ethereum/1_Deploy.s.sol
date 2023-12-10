pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../../src/core/ClientChainGateway.sol";
import "../../src/core/Vault.sol";
import "../../src/core/ExocoreGateway.sol";
import "@layerzero-contracts/mocks/LZEndpointMock.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/interfaces/precompiles/IDeposit.sol";
import "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";

contract DeployScript is Script {
    Player[] players;
    address[] whitelistTokens;
    Player exocoreValidatorSet;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    Vault vault;
    ExocoreGateway exocoreGateway;
    LZEndpointMock clientChainLzEndpoint;
    LZEndpointMock exocoreLzEndpoint;

    uint16 exocoreChainID = 9001;

    struct Player {
        uint256 privateKey;
        address addr;
    }
    
    function setUp() public {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});
    }

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("ANVIL_DEPLOYER_PRIVATE_KEY");
        vm.startBroadCast(deployerPrivateKey);

        restakeToken = new ERC20PresetFixedSupply(
            "rest",
            "rest",
            1e16,
            exocoreValidatorSet.addr
        );

        whitelistTokens.push(address(restakeToken));

        ProxyAdmin proxyAdmin = new ProxyAdmin();
        
        ClientChainGateway clientGatewayLogic = new ClientChainGateway();
        clientGateway = ClientChainGateway(address(new TransparentUpgradeableProxy(address(clientGatewayLogic), address(proxyAdmin), "")));

        Vault vaultLogic = new Vault();
        vault = Vault(address(new TransparentUpgradeableProxy(address(vaultLogic), address(proxyAdmin), "")));

        clientChainLzEndpoint = new LZEndpointMock(clientchainIdssss);

        clientGateway.initialize(payable(exocoreValidatorSet.addr), whitelistTokens, address(clientChainLzEndpoint), exocoreChainID);
        vault.initialize(address(restakeToken), address(clientGateway));

        vaults.push(address(vault));
        vm.stopBroadCast();
        
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        clientGateway.addTokenVaults(vaults);
    }
}
