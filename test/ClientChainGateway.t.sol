pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "@layerzero-contracts/mocks/LZEndpointMock.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../src/interfaces/ITSSReceiver.sol";

contract ClientChainGatewayTest is Test {
    Player[] players;
    address[] whitelistTokens;
    Player exocoreValidatorSet;
    Player deployer;
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

    event Paused(address account);
    event Unpaused(address account);

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});
        deployer = Player({privateKey: uint256(0xb), addr: vm.addr(uint256(0xb))});

        _deploy();

        vm.prank(exocoreValidatorSet.addr);
        clientGateway.addTokenVaults(vaults);
    }

    function _deploy() internal {
        vm.startPrank(deployer.addr);

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

        clientChainLzEndpoint = new LZEndpointMock(clientChainID);

        clientGateway.initialize(payable(exocoreValidatorSet.addr), whitelistTokens, address(clientChainLzEndpoint), exocoreChainID);
        vault.initialize(address(restakeToken), address(clientGateway));
        vaults.push(address(vault));
        vm.stopPrank();
    }

    function test_PauseClientChainGateway() public {
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit Paused(exocoreValidatorSet.addr);
        vm.prank(exocoreValidatorSet.addr);
        clientGateway.pause();
        assertEq(clientGateway.paused(), true);
    }

    function test_UnpauseClientChainGateway() public {
        vm.startPrank(exocoreValidatorSet.addr);

        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit Paused(exocoreValidatorSet.addr);
        clientGateway.pause();
        assertEq(clientGateway.paused(), true);

        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit Unpaused(exocoreValidatorSet.addr);
        clientGateway.unpause();
        assertEq(clientGateway.paused(), false);
    }

    function test_RevertWhen_UnauthorizedPauser() public {
        vm.expectRevert("only Exocore validator set aggregated address could call this");
        vm.startPrank(deployer.addr);
        clientGateway.pause();
    }

    function test_RevertWhen_CallDisabledFunctionsWhenPaused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        clientGateway.pause();

        vm.expectRevert("Pausable: paused");
        clientGateway.addTokenVaults(vaults);

        vm.expectRevert("Pausable: paused");
        clientGateway.claim(address(restakeToken), uint256(1), deployer.addr);

        vm.expectRevert("Pausable: paused");
        clientGateway.delegateTo(bytes32(bytes20(deployer.addr)), address(restakeToken), uint256(1));

        vm.expectRevert("Pausable: paused");
        clientGateway.deposit(address(restakeToken), uint256(1));

        vm.expectRevert("Pausable: paused");
        clientGateway.withdrawPrincipleFromExocore(address(restakeToken), uint256(1));

        vm.expectRevert("Pausable: paused");
        clientGateway.undelegateFrom(bytes32(bytes20(deployer.addr)), address(restakeToken), uint256(1));

        vm.expectRevert("Pausable: paused");
        ITSSReceiver.InterchainMsg memory msg_;
        clientGateway.receiveInterchainMsg(msg_, bytes(""));
    }
}