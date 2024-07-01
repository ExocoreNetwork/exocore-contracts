pragma solidity ^0.8.19;

import {NonShortCircuitEndpointV2Mock} from "../../mocks/NonShortCircuitEndpointV2Mock.sol";
import "src/interfaces/precompiles/IAssets.sol";
import "src/interfaces/precompiles/IClaimReward.sol";
import "src/interfaces/precompiles/IDelegation.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";
import "src/core/ClientChainGateway.sol";

import "src/core/ClientChainGateway.sol";
import "src/core/ExocoreGateway.sol";
import {Vault} from "src/core/Vault.sol";

import {GatewayStorage} from "src/storage/GatewayStorage.sol";

contract SetUp is Test {

    using AddressCast for address;

    Player[] players;
    Player exocoreValidatorSet;
    Player deployer;
    Player withdrawer;

    ExocoreGateway exocoreGateway;
    ClientChainGateway clientGateway;
    NonShortCircuitEndpointV2Mock exocoreLzEndpoint;
    NonShortCircuitEndpointV2Mock clientLzEndpoint;
    ERC20 restakeToken;

    uint16 exocoreChainId = 1;
    uint16 clientChainId = 2;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    event Paused(address account);
    event Unpaused(address account);
    event ExocorePrecompileError(address indexed precompile, uint64 nonce);

    error EnforcedPause();
    error ExpectedPause();

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});
        deployer = Player({privateKey: uint256(0xb), addr: vm.addr(uint256(0xb))});
        withdrawer = Player({privateKey: uint256(0xc), addr: vm.addr(uint256(0xb))});
        clientGateway = ClientChainGateway(payable(address(0xd)));

        // bind precompile mock contracts code to constant precompile address
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);

        _deploy();
    }

    function _deploy() internal {
        vm.startPrank(deployer.addr);

        restakeToken = new ERC20PresetFixedSupply("rest", "rest", 1e34, exocoreValidatorSet.addr);

        exocoreLzEndpoint = new NonShortCircuitEndpointV2Mock(exocoreChainId, exocoreValidatorSet.addr);
        clientLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet.addr);

        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway(address(exocoreLzEndpoint));
        exocoreGateway = ExocoreGateway(
            payable(address(new TransparentUpgradeableProxy(address(exocoreGatewayLogic), address(proxyAdmin), "")))
        );

        exocoreGateway.initialize(payable(exocoreValidatorSet.addr));
        vm.stopPrank();

        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.setPeer(clientChainId, address(clientGateway).toBytes32());

        exocoreLzEndpoint.setDestLzEndpoint(address(clientGateway), address(clientLzEndpoint));

        // transfer some gas fee to exocore gateway as it has to pay for the relay fee to layerzero endpoint when
        // sending back response
        deal(address(exocoreGateway), 1e22);
    }

}

contract Pausable is SetUp {

    using AddressCast for address;

    function test_PauseExocoreGateway() public {
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit Paused(exocoreValidatorSet.addr);
        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.pause();
        assertEq(exocoreGateway.paused(), true);
    }

    function test_UnpauseExocoreGateway() public {
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
        vm.expectRevert(bytes("ExocoreGateway: caller is not Exocore validator set aggregated address"));
        vm.startPrank(deployer.addr);
        exocoreGateway.pause();
    }

    function test_RevertWhen_CallDisabledFunctionsWhenPaused() public {
        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        vm.prank(address(exocoreLzEndpoint));
        vm.expectRevert(EnforcedPause.selector);
        exocoreGateway.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(1)),
            bytes32(0),
            bytes(""),
            address(0x2),
            bytes("")
        );
    }

}

contract LzReceive is SetUp {

    using AddressCast for address;

    uint256 constant WITHDRAWAL_AMOUNT = 123;

    function test_NotRevert_WithdrawalAmountOverflow() public {
        bytes memory payload = abi.encodePacked(
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(withdrawer.addr))),
            uint256(WITHDRAWAL_AMOUNT)
        );
        bytes memory msg_ = abi.encodePacked(GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit ExocorePrecompileError(ASSETS_PRECOMPILE_ADDRESS, uint64(1));

        vm.prank(address(exocoreLzEndpoint));
        exocoreGateway.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(1)),
            bytes32(0),
            msg_,
            address(0x2),
            bytes("")
        );
    }

}

contract AddWhitelistTokens is SetUp {

    using stdStorage for StdStorage;

    function test_RevertWhen_CallerNotOwner() public {
        address[] memory whitelistTokens = new address[](2);
        uint256[] memory tvlLimits = new uint256[](2);
        uint messageLength = TOKEN_ADDRESS_BYTES_LENTH * whitelistTokens.length + 2;
        uint256 nativeFee = clientGateway.quote(new bytes());

        vm.startPrank(deployer.addr);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, deployer.addr));
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        clientGateway.pause();

        address[] memory whitelistTokens = new address[](2);
        uint256 nativeFee = clientGateway.quote(new bytes(TOKEN_ADDRESS_BYTES_LENTH * whitelistTokens.length + 2));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_TokensListTooLong() public {
        address[] memory whitelistTokens = new address[](256);
        uint256 nativeFee = clientGateway.quote(new bytes(TOKEN_ADDRESS_BYTES_LENTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ClientChainGateway: tokens length should not execeed 255");
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_LengthNotMatch() public {
        address[] memory whitelistTokens = new address[](2);
        uint256[] memory tvlLimits = new uint256[](3);
        uint256 nativeFee = clientGateway.quote(new bytes(TOKEN_ADDRESS_BYTES_LENTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ClientChainGateway: tokens length should not execeed 255");
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_RevertWhen_HasZeroAddressToken() public {
        address[] memory whitelistTokens = new address[](2);
        whitelistTokens[0] = address(restakeToken);
        uint256 nativeFee = clientGateway.quote(new bytes(TOKEN_ADDRESS_BYTES_LENTH * whitelistTokens.length + 2));

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
        uint256 nativeFee = clientGateway.quote(new bytes(TOKEN_ADDRESS_BYTES_LENTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ClientChainGateway: token should not be whitelisted before");
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

    function test_SendMessage() public {
        address[] memory whitelistTokens = new address[](1);
        whitelistTokens[0] = address(restakeToken);
        uint256 nativeFee = clientGateway.quote(new bytes(TOKEN_ADDRESS_BYTES_LENTH * whitelistTokens.length + 2));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_REGISTER_TOKENS, generateUID(1, true), 1, nativeFee);
        clientGateway.addWhitelistTokens{value: nativeFee}(whitelistTokens);
    }

}