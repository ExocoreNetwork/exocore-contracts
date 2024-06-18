pragma solidity ^0.8.19;

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";

import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";
import "@openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "src/core/ClientChainGateway.sol";

import "src/core/ExoCapsule.sol";
import "src/core/ExocoreGateway.sol";
import {Vault} from "src/core/Vault.sol";
import "src/storage/GatewayStorage.sol";

import {NonShortCircuitEndpointV2Mock} from "../../mocks/NonShortCircuitEndpointV2Mock.sol";
import "src/interfaces/IExoCapsule.sol";
import "src/interfaces/IVault.sol";

import "src/core/BeaconProxyBytecode.sol";

contract SetUp is Test {

    using AddressCast for address;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    // bytes32 token + bytes32 depositor + uint256 amount
    uint256 internal constant DEPOSIT_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DELEGATE_REQUEST_LENGTH = 138;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant UNDELEGATE_REQUEST_LENGTH = 138;
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant WITHDRAW_PRINCIPLE_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant CLAIM_REWARD_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH = DELEGATE_REQUEST_LENGTH;
    uint256 internal constant ADDRESS_LENGTH = 32;

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
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon capsuleBeacon;
    BeaconProxyBytecode beaconProxyBytecode;

    string operatorAddress = "exo1v4s6vtjpmxwu9rlhqms5urzrc3tc2ae2gnuqhc";
    uint16 exocoreChainId = 2;
    uint16 clientChainId = 1;

    event Paused(address account);
    event Unpaused(address account);
    event MessageSent(GatewayStorage.Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

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

        beaconOracle = IBeaconChainOracle(_deployBeaconOracle());

        vaultImplementation = new Vault();
        capsuleImplementation = new ExoCapsule();

        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));

        beaconProxyBytecode = new BeaconProxyBytecode();

        restakeToken = new ERC20PresetFixedSupply("rest", "rest", 1e16, exocoreValidatorSet.addr);
        whitelistTokens.push(address(restakeToken));

        clientChainLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet.addr);
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        clientGatewayLogic = new ClientChainGateway(
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
        vm.expectRevert("ClientChainGateway: caller is not Exocore validator set aggregated address");
        vm.startPrank(deployer.addr);
        clientGateway.pause();
    }

    function test_RevertWhen_CallDisabledFunctionsWhenPaused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        clientGateway.pause();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        clientGateway.claim(address(restakeToken), uint256(1), deployer.addr);

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        clientGateway.delegateTo(operatorAddress, address(restakeToken), uint256(1));

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        clientGateway.deposit(address(restakeToken), uint256(1));

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        clientGateway.withdrawPrincipleFromExocore(address(restakeToken), uint256(1));

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
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

    function test_ExocoreValidatoSetAddressInitialized() public {
        assertEq(clientGateway.exocoreValidatorSetAddress(), exocoreValidatorSet.addr);
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

contract AddWhitelistTokens is SetUp {

    using stdStorage for StdStorage;

    function test_RevertWhen_CallerNotOwner() public {
        address[] memory whitelistTokens = new address[](2);
        uint256 nativeFee = clientGateway.quote(new bytes(ADDRESS_LENGTH * whitelistTokens.length + 2));

        vm.startPrank(deployer.addr);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, deployer.addr));
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        clientGateway.pause();

        address[] memory whitelistTokens = new address[](2);
        uint256 nativeFee = clientGateway.quote(new bytes(ADDRESS_LENGTH * whitelistTokens.length + 2));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_TokensListTooLong() public {
        address[] memory whitelistTokens = new address[](256);
        uint256 nativeFee = clientGateway.quote(new bytes(ADDRESS_LENGTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ClientChainGateway: tokens length should not execeed 255");
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_HasZeroAddressToken() public {
        address[] memory whitelistTokens = new address[](2);
        whitelistTokens[0] = address(restakeToken);
        uint256 nativeFee = clientGateway.quote(new bytes(ADDRESS_LENGTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ClientChainGateway: zero token address");
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_HasAlreadyWhitelistedToken() public {
        // we use this hacking way to find the slot of `isWhitelistedToken(address(restakeToken))` and set its value to
        // true
        bytes32 whitelistedSlot = bytes32(
            stdstore.target(address(clientGatewayLogic)).sig("isWhitelistedToken(address)").with_key(
                address(restakeToken)
            ).find()
        );
        vm.store(address(clientGateway), whitelistedSlot, bytes32(uint256(1)));

        address[] memory whitelistTokens = new address[](1);
        whitelistTokens[0] = address(restakeToken);
        uint256 nativeFee = clientGateway.quote(new bytes(ADDRESS_LENGTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ClientChainGateway: token should not be whitelisted before");
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_SendMessage() public {
        address[] memory whitelistTokens = new address[](1);
        whitelistTokens[0] = address(restakeToken);
        uint256 nativeFee = clientGateway.quote(new bytes(ADDRESS_LENGTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_REGISTER_TOKENS, generateUID(1, true), 1, nativeFee);
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

}
