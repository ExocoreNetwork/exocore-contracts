pragma solidity ^0.8.19;

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";

import "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

import {Origin} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";

import "forge-std/Test.sol";

import "src/core/ClientChainGateway.sol";

import {BootstrapStorage} from "src/storage/BootstrapStorage.sol";
import "src/storage/ClientChainGatewayStorage.sol";

import "src/core/ExoCapsule.sol";
import "src/core/ExocoreGateway.sol";
import {Vault} from "src/core/Vault.sol";
import {Action, GatewayStorage} from "src/storage/GatewayStorage.sol";

import {NonShortCircuitEndpointV2Mock} from "../../mocks/NonShortCircuitEndpointV2Mock.sol";

import {RewardVault} from "src/core/RewardVault.sol";
import "src/interfaces/IExoCapsule.sol";
import {IRewardVault} from "src/interfaces/IRewardVault.sol";
import "src/interfaces/IVault.sol";

import {Errors} from "src/libraries/Errors.sol";
import {NetworkConstants} from "src/libraries/NetworkConstants.sol";
import "src/utils/BeaconProxyBytecode.sol";

contract SetUp is Test {

    using AddressCast for address;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    Player[] players;
    address[] whitelistTokens;
    Player exocoreValidatorSet;
    Player deployer;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    ClientChainGateway clientGatewayLogic;
    ExocoreGateway exocoreGateway;
    ILayerZeroEndpointV2 clientChainLzEndpoint;
    ILayerZeroEndpointV2 exocoreLzEndpoint;
    IBeaconChainOracle beaconOracle;
    IVault vaultImplementation;
    IRewardVault rewardVaultImplementation;
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon rewardVaultBeacon;
    IBeacon capsuleBeacon;
    BeaconProxyBytecode beaconProxyBytecode;

    string operatorAddress = "exo1v4s6vtjpmxwu9rlhqms5urzrc3tc2ae2gnuqhc";
    uint32 exocoreChainId = 2;
    uint32 clientChainId = 1;

    event Paused(address account);
    event Unpaused(address account);
    event MessageSent(Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});
        deployer = Player({privateKey: uint256(0xb), addr: vm.addr(uint256(0xb))});
        exocoreGateway = ExocoreGateway(payable(address(0xc)));
        exocoreLzEndpoint = ILayerZeroEndpointV2(address(0xd));

        vm.deal(exocoreValidatorSet.addr, 100 ether);
        vm.deal(deployer.addr, 100 ether);

        vm.chainId(clientChainId);
        _deploy();

        NonShortCircuitEndpointV2Mock(address(clientChainLzEndpoint)).setDestLzEndpoint(
            address(exocoreGateway), address(exocoreLzEndpoint)
        );

        vm.prank(exocoreValidatorSet.addr);
        clientGateway.setPeer(exocoreChainId, address(exocoreGateway).toBytes32());
        vm.stopPrank();
    }

    function _deploy() internal {
        vm.startPrank(deployer.addr);

        beaconOracle = IBeaconChainOracle(new EigenLayerBeaconOracle(NetworkConstants.getBeaconGenesisTimestamp()));

        vaultImplementation = new Vault();
        rewardVaultImplementation = new RewardVault();
        capsuleImplementation = new ExoCapsule(address(0));

        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        rewardVaultBeacon = new UpgradeableBeacon(address(rewardVaultImplementation));
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));

        beaconProxyBytecode = new BeaconProxyBytecode();

        restakeToken = new ERC20PresetFixedSupply("rest", "rest", 1e16, exocoreValidatorSet.addr);
        whitelistTokens.push(address(restakeToken));

        clientChainLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet.addr);
        ProxyAdmin proxyAdmin = new ProxyAdmin();

        BootstrapStorage.ImmutableConfig memory config = BootstrapStorage.ImmutableConfig({
            exocoreChainId: exocoreChainId,
            beaconOracleAddress: address(beaconOracle),
            vaultBeacon: address(vaultBeacon),
            exoCapsuleBeacon: address(capsuleBeacon),
            beaconProxyBytecode: address(beaconProxyBytecode),
            networkConfig: address(0)
        });

        clientGatewayLogic = new ClientChainGateway(address(clientChainLzEndpoint), config, address(rewardVaultBeacon));

        clientGateway = ClientChainGateway(
            payable(address(new TransparentUpgradeableProxy(address(clientGatewayLogic), address(proxyAdmin), "")))
        );

        clientGateway.initialize(payable(exocoreValidatorSet.addr));

        vm.stopPrank();
    }

    function generateUID(uint64 nonce, bool fromClientChainToExocore) internal view returns (bytes32 uid) {
        if (fromClientChainToExocore) {
            uid = GUID.generate(
                nonce, clientChainId, address(clientGateway), exocoreChainId, address(exocoreGateway).toBytes32()
            );
        } else {
            uid = GUID.generate(
                nonce, exocoreChainId, address(exocoreGateway), clientChainId, address(clientGateway).toBytes32()
            );
        }
    }

}

contract Pausable is SetUp {

    using stdStorage for StdStorage;

    function setUp() public override {
        super.setUp();

        // we use this hacking way to find the slot of `isWhitelistedToken(address(restakeToken))` and set its value to
        // true
        bytes32 whitelistedSlot = bytes32(
            stdstore.target(address(clientGatewayLogic)).sig("isWhitelistedToken(address)").with_key(
                address(restakeToken)
            ).find()
        );
        vm.store(address(clientGateway), whitelistedSlot, bytes32(uint256(1)));
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
        emit PausableUpgradeable.Paused(exocoreValidatorSet.addr);
        clientGateway.pause();
        assertEq(clientGateway.paused(), true);

        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit PausableUpgradeable.Unpaused(exocoreValidatorSet.addr);
        clientGateway.unpause();
        assertEq(clientGateway.paused(), false);
    }

    function test_RevertWhen_UnauthorizedPauser() public {
        vm.expectRevert("Ownable: caller is not the owner");
        vm.startPrank(deployer.addr);
        clientGateway.pause();
    }

    function test_RevertWhen_CallDisabledFunctionsWhenPaused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        clientGateway.pause();

        vm.expectRevert("Pausable: paused");
        clientGateway.withdrawPrincipal(address(restakeToken), uint256(1), deployer.addr);

        vm.expectRevert("Pausable: paused");
        clientGateway.delegateTo(operatorAddress, address(restakeToken), uint256(1));

        vm.expectRevert("Pausable: paused");
        clientGateway.deposit(address(restakeToken), uint256(1));

        vm.expectRevert("Pausable: paused");
        clientGateway.claimPrincipalFromExocore(address(restakeToken), uint256(1));

        vm.expectRevert("Pausable: paused");
        clientGateway.undelegateFrom(operatorAddress, address(restakeToken), uint256(1));
    }

}

contract Initialize is SetUp {

    function test_ExocoreChainIdInitialized() public {
        assertEq(clientGateway.EXOCORE_CHAIN_ID(), exocoreChainId);
    }

    function test_LzEndpointInitialized() public {
        assertFalse(address(clientChainLzEndpoint) == address(0));
        assertEq(address(clientGateway.endpoint()), address(clientChainLzEndpoint));
    }

    function test_VaultBeaconInitialized() public {
        assertFalse(address(vaultBeacon) == address(0));
        assertEq(address(clientGateway.VAULT_BEACON()), address(vaultBeacon));
    }

    function test_BeaconProxyByteCodeInitialized() public {
        assertFalse(address(beaconProxyBytecode) == address(0));
        assertEq(address(clientGateway.BEACON_PROXY_BYTECODE()), address(beaconProxyBytecode));
    }

    function test_BeaconOracleInitialized() public {
        assertFalse(address(beaconOracle) == address(0));
        assertEq(clientGateway.BEACON_ORACLE_ADDRESS(), address(beaconOracle));
    }

    function test_ExoCapsuleBeaconInitialized() public {
        assertFalse(address(capsuleBeacon) == address(0));
        assertEq(address(clientGateway.EXO_CAPSULE_BEACON()), address(capsuleBeacon));
    }

    function test_OwnerInitialized() public {
        assertEq(clientGateway.owner(), exocoreValidatorSet.addr);
    }

    function test_NotPaused() public {
        assertFalse(clientGateway.paused());
    }

    function test_Bootstrapped() public {
        assertTrue(clientGateway.bootstrapped());
    }

}

contract WithdrawNonBeaconChainETHFromCapsule is SetUp {

    using stdStorage for StdStorage;

    address payable user;
    address payable capsuleAddress;
    uint256 depositAmount = 1 ether;
    uint256 withdrawAmount = 0.5 ether;

    address internal constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    function setUp() public override {
        super.setUp();

        // we use this hacking way to add virtual staked ETH to the whitelist to enable native restaking
        bytes32 whitelistedSlot = bytes32(
            stdstore.target(address(clientGatewayLogic)).sig("isWhitelistedToken(address)").with_key(
                VIRTUAL_STAKED_ETH_ADDRESS
            ).find()
        );
        vm.store(address(clientGateway), whitelistedSlot, bytes32(uint256(1)));

        user = payable(players[0].addr);
        vm.deal(user, 10 ether);

        // 1. User creates capsule through ClientChainGateway
        vm.prank(user);
        capsuleAddress = payable(clientGateway.createExoCapsule());
    }

    function test_success_withdrawNonBeaconChainETH() public {
        // 2. User directly transfers some ETH to created capsule
        vm.prank(user);
        (bool success,) = capsuleAddress.call{value: depositAmount}("");
        require(success, "ETH transfer failed");

        uint256 userBalanceBefore = user.balance;
        uint256 capsuleBalanceBefore = capsuleAddress.balance;

        // 3. User withdraws ETH by calling withdrawNonBeaconChainETHFromCapsule
        vm.prank(user);
        clientGateway.withdrawNonBeaconChainETHFromCapsule(user, withdrawAmount);

        // Assert balance changes
        assertEq(user.balance, userBalanceBefore + withdrawAmount, "User balance didn't increase correctly");
        assertEq(
            capsuleAddress.balance, capsuleBalanceBefore - withdrawAmount, "Capsule balance didn't decrease correctly"
        );
    }

    function test_revert_capsuleNotFound() public {
        address payable userWithoutCapsule = payable(address(0x123));

        vm.prank(userWithoutCapsule);
        vm.expectRevert(Errors.CapsuleDoesNotExist.selector);
        clientGateway.withdrawNonBeaconChainETHFromCapsule(userWithoutCapsule, withdrawAmount);
    }

    function test_revert_insufficientBalance() public {
        // User directly transfers some ETH to created capsule
        vm.prank(user);
        (bool success,) = capsuleAddress.call{value: depositAmount}("");
        require(success, "ETH transfer failed");

        uint256 excessiveWithdrawAmount = 2 ether;

        vm.prank(user);
        vm.expectRevert(
            "ExoCapsule.withdrawNonBeaconChainETHBalance: amountToWithdraw is greater than nonBeaconChainETHBalance"
        );
        clientGateway.withdrawNonBeaconChainETHFromCapsule(user, excessiveWithdrawAmount);
    }

}

contract WithdrawalPrincipalFromExocore is SetUp {

    using stdStorage for StdStorage;
    using AddressCast for address;

    address internal constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 constant WITHDRAWAL_AMOUNT = 1 ether;

    address payable user;

    function setUp() public override {
        super.setUp();

        user = payable(players[0].addr);
        vm.deal(user, 10 ether);

        bytes32[] memory tokens = new bytes32[](2);
        tokens[0] = bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS));
        tokens[1] = bytes32(bytes20(address(restakeToken)));

        // Simulate adding VIRTUAL_STAKED_ETH_ADDRESS to whitelist via lzReceive
        bytes memory message =
            abi.encodePacked(Action.REQUEST_ADD_WHITELIST_TOKEN, abi.encodePacked(tokens[0], uint128(0)));
        Origin memory origin = Origin({srcEid: exocoreChainId, sender: address(exocoreGateway).toBytes32(), nonce: 1});

        vm.prank(address(clientChainLzEndpoint));
        clientGateway.lzReceive(origin, bytes32(0), message, address(0), bytes(""));
        // assert that VIRTUAL_STAKED_ETH_ADDRESS and restake token is whitelisted
        assertTrue(clientGateway.isWhitelistedToken(VIRTUAL_STAKED_ETH_ADDRESS));
        origin.nonce = 2;
        message = abi.encodePacked(
            Action.REQUEST_ADD_WHITELIST_TOKEN, abi.encodePacked(tokens[1], uint128(restakeToken.totalSupply() / 20))
        );
        vm.prank(address(clientChainLzEndpoint));
        clientGateway.lzReceive(origin, bytes32(0), message, address(0), bytes(""));
        assertTrue(clientGateway.isWhitelistedToken(address(restakeToken)));
    }

    function test_revert_withdrawVirtualStakedETH() public {
        // Try to withdraw VIRTUAL_STAKED_ETH
        vm.prank(user);
        vm.expectRevert(Errors.VaultDoesNotExist.selector);
        clientGateway.claimPrincipalFromExocore(VIRTUAL_STAKED_ETH_ADDRESS, WITHDRAWAL_AMOUNT);
    }

    function test_revert_withdrawNonWhitelistedToken() public {
        address nonWhitelistedToken = address(0x1234);

        vm.prank(players[0].addr);
        vm.expectRevert("BootstrapStorage: token is not whitelisted");
        clientGateway.claimPrincipalFromExocore(nonWhitelistedToken, WITHDRAWAL_AMOUNT);
    }

    function test_revert_withdrawZeroAmount() public {
        vm.prank(user);
        vm.expectRevert("BootstrapStorage: amount should be greater than zero");
        clientGateway.claimPrincipalFromExocore(address(restakeToken), 0);
    }

}
