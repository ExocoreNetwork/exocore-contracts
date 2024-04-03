pragma solidity ^0.8.19;

import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../../src/core/ClientChainGateway.sol";
import {Vault} from "../../src/core/Vault.sol";
import "../../src/core/ExocoreGateway.sol";
import {EndpointV2Mock} from "../mocks/EndpointV2Mock.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/interfaces/precompiles/IDeposit.sol";
import "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../../src/interfaces/ITSSReceiver.sol";

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
    EndpointV2Mock clientChainLzEndpoint;
    EndpointV2Mock exocoreLzEndpoint;

    string operatorAddress = "exo1v4s6vtjpmxwu9rlhqms5urzrc3tc2ae2gnuqhc";
    uint16 exocoreChainId = 1;
    uint16 clientChainId = 2;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    event Paused(address account);
    event Unpaused(address account);

    error EnforcedPause();
    error ExpectedPause();

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

        restakeToken = new ERC20PresetFixedSupply("rest", "rest", 1e16, exocoreValidatorSet.addr);
        whitelistTokens.push(address(restakeToken));

        clientChainLzEndpoint = new EndpointV2Mock(clientChainId);
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(address(clientChainLzEndpoint));
        clientGateway = ClientChainGateway(
            payable(address(new TransparentUpgradeableProxy(address(clientGatewayLogic), address(proxyAdmin), "")))
        );

        Vault vaultLogic = new Vault();
        vault = Vault(address(new TransparentUpgradeableProxy(address(vaultLogic), address(proxyAdmin), "")));

        clientGateway.initialize(exocoreChainId, payable(exocoreValidatorSet.addr), whitelistTokens);
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
        vm.expectRevert("ClientChainGateway: caller is not Exocore validator set aggregated address");
        vm.startPrank(deployer.addr);
        clientGateway.pause();
    }

    function test_RevertWhen_CallDisabledFunctionsWhenPaused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        clientGateway.pause();

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.addTokenVaults(vaults);

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.claim(address(restakeToken), uint256(1), deployer.addr);

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.delegateTo(operatorAddress, address(restakeToken), uint256(1));

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.deposit(address(restakeToken), uint256(1));

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.withdrawPrincipleFromExocore(address(restakeToken), uint256(1));

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.undelegateFrom(operatorAddress, address(restakeToken), uint256(1));

        vm.expectRevert(EnforcedPause.selector);
        ITSSReceiver.InterchainMsg memory msg_;
        clientGateway.receiveInterchainMsg(msg_, bytes(""));
    }
}
