pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import "../src/core/Vault.sol";
import "../src/core/ExocoreReceiver.sol";
import "@layerzero-contracts/mocks/LZEndpointMock.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

contract ExocoreDeployer is Test {
    Player[] players;
    address[] whitelistTokens;
    Player exocoreValidatorSet;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    Gateway gateway;
    Vault vault;
    ExocoreReceiver exocoreReceiver;
    LZEndpointMock clientChainLzEndpoint;
    LZEndpointMock exocoreLzEndpoint;

    uint16 exocoreChainID = 0;
    uint16 clientChainID = 1;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});
        restakeToken = new ERC20PresetFixedSupply(
            "rest",
            "rest",
            1e16,
            exocoreValidatorSet.addr
        );
        whitelistTokens.push(address(restakeToken));

        _deploy();

        vaults.push(address(vault));
        vm.prank(exocoreValidatorSet.addr);
        gateway.addTokenVaults(vaults);
    }

    function _deploy() internal {
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        
        Gateway gatewayLogic = new Gateway();
        gateway = Gateway(address(new TransparentUpgradeableProxy(address(gatewayLogic), address(proxyAdmin), "")));

        Vault vaultLogic = new Vault();
        vault = Vault(address(new TransparentUpgradeableProxy(address(vaultLogic), address(proxyAdmin), "")));

        ExocoreReceiver exocoreReceiverLogic = new ExocoreReceiver();
        exocoreReceiver = ExocoreReceiver(address(new TransparentUpgradeableProxy(address(exocoreReceiverLogic), address(proxyAdmin), "")));

        clientChainLzEndpoint = new LZEndpointMock(clientChainID);
        exocoreLzEndpoint = new LZEndpointMock(exocoreChainID);
        clientChainLzEndpoint.setDestLzEndpoint(address(exocoreReceiver), address(exocoreLzEndpoint));

        gateway.initialize(payable(exocoreValidatorSet.addr), whitelistTokens, address(clientChainLzEndpoint), exocoreChainID, address(exocoreReceiver));
        vault.initialize(address(restakeToken), address(gateway));
        exocoreReceiver.initialize(exocoreValidatorSet.addr, address(exocoreLzEndpoint));
    }
}