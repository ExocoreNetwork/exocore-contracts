pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../../src/core/ClientChainGateway.sol";
import "../../src/core/Vault.sol";
import "../../src/core/ExocoreGateway.sol";
import "@layerzero-contracts/mocks/LZEndpointMock.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/interfaces/precompiles/IDeposit.sol";
import "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";

contract ExocoreDeployer is Test {
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
        clientGateway.addTokenVaults(vaults);
    }

    function _deploy() internal {
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        
        ClientChainGateway clientGatewayLogic = new ClientChainGateway();
        clientGateway = ClientChainGateway(address(new TransparentUpgradeableProxy(address(clientGatewayLogic), address(proxyAdmin), "")));

        Vault vaultLogic = new Vault();
        vault = Vault(address(new TransparentUpgradeableProxy(address(vaultLogic), address(proxyAdmin), "")));

        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway();
        exocoreGateway = ExocoreGateway(address(new TransparentUpgradeableProxy(address(exocoreGatewayLogic), address(proxyAdmin), "")));

        clientChainLzEndpoint = new LZEndpointMock(clientChainID);
        exocoreLzEndpoint = new LZEndpointMock(exocoreChainID);
        clientChainLzEndpoint.setDestLzEndpoint(address(exocoreGateway), address(exocoreLzEndpoint));
        exocoreLzEndpoint.setDestLzEndpoint(address(clientGateway), address(clientChainLzEndpoint));

        clientGateway.initialize(payable(exocoreValidatorSet.addr), whitelistTokens, address(clientChainLzEndpoint), exocoreChainID);
        vault.initialize(address(restakeToken), address(clientGateway));
        exocoreGateway.initialize(payable(exocoreValidatorSet.addr), address(exocoreLzEndpoint));

        bytes memory deployedDepositMockCode = vm.getDeployedCode("DepositMock.sol");
        vm.etch(DEPOSIT_PRECOMPILE_ADDRESS, deployedDepositMockCode);

        bytes memory deployedDelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, deployedDelegationMockCode);

        bytes memory deployedWithdrawPrincipleMockCode = vm.getDeployedCode("WithdrawPrincipleMock.sol");
        vm.etch(WITHDRAW_PRECOMPILE_ADDRESS, deployedWithdrawPrincipleMockCode);
    }
}