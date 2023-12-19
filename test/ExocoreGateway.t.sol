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
    Player exocoreValidatorSet;
    Player deployer;

    ExocoreGateway exocoreGateway;
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
    }

    function _deploy() internal {
        vm.startPrank(deployer.addr);

        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway();
        exocoreGateway = ExocoreGateway(address(new TransparentUpgradeableProxy(address(exocoreGatewayLogic), address(proxyAdmin), "")));

        exocoreLzEndpoint = new LZEndpointMock(exocoreChainID);

        exocoreGateway.initialize(payable(exocoreValidatorSet.addr), address(exocoreLzEndpoint));
        vm.stopPrank();

        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.setTrustedRemote(clientChainID, abi.encodePacked(address(deployer.addr), address(exocoreGateway)));
    }

    function test_PauseClientChainGateway() public {
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit Paused(exocoreValidatorSet.addr);
        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.pause();
        assertEq(exocoreGateway.paused(), true);
    }

    function test_UnpauseClientChainGateway() public {
        vm.startPrank(exocoreValidatorSet.addr);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit Paused(exocoreValidatorSet.addr);
        exocoreGateway.pause();
        assertEq(exocoreGateway.paused(), true);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit Unpaused(exocoreValidatorSet.addr);
        exocoreGateway.unpause();
        assertEq(exocoreGateway.paused(), false);
    }

    function test_RevertWhen_UnauthorizedPauser() public {
        vm.expectRevert("only Exocore validator set aggregated address could call this");
        vm.startPrank(deployer.addr);
        exocoreGateway.pause();
    }

    function test_RevertWhen_CallDisabledFunctionsWhenPaused() public {
        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        vm.prank(address(exocoreLzEndpoint));
        vm.expectRevert("Pausable: paused");
        exocoreGateway.lzReceive(
            clientChainID, 
            abi.encodePacked(address(deployer.addr), address(exocoreGateway)), 
            uint64(1), 
            bytes("")
        );
    }
}