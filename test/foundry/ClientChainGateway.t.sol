pragma solidity ^0.8.19;

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";
import "@openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/core/ClientChainGateway.sol";

import "../../src/core/ExoCapsule.sol";
import "../../src/core/ExocoreGateway.sol";
import {Vault} from "../../src/core/Vault.sol";

import "../../src/interfaces/IExoCapsule.sol";
import "../../src/interfaces/IVault.sol";
import {EndpointV2Mock} from "../mocks/EndpointV2Mock.sol";

import "src/core/BeaconProxyBytecode.sol";

contract SetUp is Test {
    using stdStorage for StdStorage;

    Player[] players;
    address[] whitelistTokens;
    Player exocoreValidatorSet;
    Player deployer;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    ExocoreGateway exocoreGateway;
    EndpointV2Mock clientChainLzEndpoint;
    EndpointV2Mock exocoreLzEndpoint;
    IBeaconChainOracle beaconOracle;
    IVault vaultImplementation;
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon capsuleBeacon;
    BeaconProxyBytecode beaconProxyBytecode;

    string operatorAddress = "exo1v4s6vtjpmxwu9rlhqms5urzrc3tc2ae2gnuqhc";
    uint16 exocoreChainId = 2;
    uint16 clientChainId = 1;

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

        vm.chainId(clientChainId);
        _deploy();
    }

    function _deploy() internal {
        vm.startPrank(deployer.addr);

        beaconOracle = IBeaconChainOracle(_deployBeaconOracle());

        vaultImplementation = new Vault();
        capsuleImplementation = new ExoCapsule();

        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));

        beaconProxyBytecode = new BeaconProxyBytecode();

        restakeToken = new ERC20PresetFixedSupply("rest", "rest", 1e16, exocoreValidatorSet.addr);
        whitelistTokens.push(address(restakeToken));

        clientChainLzEndpoint = new EndpointV2Mock(clientChainId);
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(beaconOracle),
            address(vaultBeacon),
            address(capsuleBeacon),
            address(beaconProxyBytecode)
        );
        clientGateway = ClientChainGateway(
            payable(address(new TransparentUpgradeableProxy(address(clientGatewayLogic), address(proxyAdmin), "")))
        );

        clientGateway.initialize(payable(exocoreValidatorSet.addr));

        vm.stopPrank();

        // we use this hacking way to find the slot of `isWhitelistedToken(address(restakeToken))` and set its value to true
        bytes32 whitelistedSlot = bytes32(
            stdstore
                .target(address(clientGatewayLogic))
                .sig("isWhitelistedToken(address)")
                .with_key(address(restakeToken))
                .find()
        );
        vm.store(address(clientGateway), whitelistedSlot, bytes32(uint256(1)));
    }

    function _deployBeaconOracle() internal returns (EigenLayerBeaconOracle) {
        uint256 GENESIS_BLOCK_TIMESTAMP;

        // mainnet
        if (block.chainid == 1) {
            GENESIS_BLOCK_TIMESTAMP = 1_606_824_023;
            // goerli
        } else if (block.chainid == 5) {
            GENESIS_BLOCK_TIMESTAMP = 1_616_508_000;
            // sepolia
        } else if (block.chainid == 11_155_111) {
            GENESIS_BLOCK_TIMESTAMP = 1_655_733_600;
            // holesky
        } else if (block.chainid == 17_000) {
            GENESIS_BLOCK_TIMESTAMP = 1_695_902_400;
        } else {
            revert("Unsupported chainId.");
        }

        EigenLayerBeaconOracle oracle = new EigenLayerBeaconOracle(GENESIS_BLOCK_TIMESTAMP);
        return oracle;
    }

}

contract Pausable is SetUp {
    
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
        clientGateway.claim(address(restakeToken), uint256(1), deployer.addr);

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.delegateTo(operatorAddress, address(restakeToken), uint256(1));

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.deposit(address(restakeToken), uint256(1));

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.withdrawPrincipleFromExocore(address(restakeToken), uint256(1));

        vm.expectRevert(EnforcedPause.selector);
        clientGateway.undelegateFrom(operatorAddress, address(restakeToken), uint256(1));
    }

}
