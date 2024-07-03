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

import {ExocoreGatewayStorage} from "src/storage/ExocoreGatewayStorage.sol";
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
    event MessageSent(GatewayStorage.Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

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

        vm.deal(exocoreValidatorSet.addr, 100 ether);
        vm.deal(deployer.addr, 100 ether);
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

        vm.startPrank(exocoreValidatorSet.addr);
        exocoreLzEndpoint.setDestLzEndpoint(address(clientGateway), address(clientLzEndpoint));
        exocoreGateway.registerOrUpdateClientChain(
            clientChainId, address(clientGateway).toBytes32(), 20, "clientChain", "EVM compatible client chain", "secp256k1"
        );
        vm.stopPrank();

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
    using AddressCast for address;

    uint256 internal constant TOKEN_ADDRESS_BYTES_LENGTH = 32;

    event WhitelistTokenAdded(uint32 clientChainId, bytes32 token);

    bytes32[] whitelistTokens;
    uint8[] decimals;
    uint256[] tvlLimits;
    string[] names;
    string[] metaData;

    function test_RevertWhen_CallerNotOwner() public {
        _prepareInputs(2);

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(deployer.addr);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, deployer.addr));
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        _prepareInputs(2);

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_ClientChainNotRegisteredBefore() public {
        uint32 anotherClientChain = 3;
        _prepareInputs(2);

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(
            abi.encodeWithSelector(ExocoreGatewayStorage.ClientChainIDNotRegisteredBefore.selector, anotherClientChain)
        );
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            anotherClientChain, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_TokensListTooLong() public {
        _prepareInputs(256);

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(ExocoreGatewayStorage.WhitelistTokensListTooLong.selector));
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_LengthNotMatch() public {
        _prepareInputs(2);
        decimals.push(18);

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(ExocoreGatewayStorage.InvalidWhitelistTokensInput.selector));
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_HasZeroAddressToken() public {
        _prepareInputs(2);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));
        tvlLimits[0] = 1e8 ether;
        tvlLimits[1] = 1e8 ether;
        names[0] = "LST-1";
        names[1] = "LST-2";
        metaData[0] = "LST token";
        metaData[1] = "LST token";

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: token cannot be zero address");
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_HasZeroTVMLimit() public {
        _prepareInputs(1);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: tvl limit should not be zero");
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_Success_AddWhiteListTokens() public {
        _prepareInputs(1);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));
        decimals[0] = 18;
        tvlLimits[0] = 1e8 ether;
        names[0] = "RestakeToken";
        metaData[0] = "ERC20 LST token";

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit WhitelistTokenAdded(clientChainId, whitelistTokens[0]);
        emit MessageSent(GatewayStorage.Action.REQUEST_ADD_WHITELIST_TOKENS, generateUID(1, false), 1, nativeFee);
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function _prepareInputs(uint256 listLength) internal {
        whitelistTokens = new bytes32[](listLength);
        decimals = new uint8[](listLength);
        tvlLimits = new uint256[](listLength);
        names = new string[](listLength);
        metaData = new string[](listLength);
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

contract UpdateWhitelistTokens is SetUp {

    using AddressCast for address;

    uint256 internal constant TOKEN_ADDRESS_BYTES_LENGTH = 32;

    event WhitelistTokenUpdated(uint32 clientChainId, bytes32 token);

    bytes32[] whitelistTokens;
    uint8[] decimals;
    uint256[] tvlLimits;
    string[] names;
    string[] metaData;

    function test_RevertWhen_CallerNotOwner() public {
        _prepareInputs(2);

        vm.startPrank(deployer.addr);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, deployer.addr));
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        _prepareInputs(2);

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_ClientChainNotRegisteredBefore() public {
        uint32 anotherClientChain = 3;
        _prepareInputs(2);

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(
            abi.encodeWithSelector(ExocoreGatewayStorage.ClientChainIDNotRegisteredBefore.selector, anotherClientChain)
        );
        exocoreGateway.updateWhitelistedTokens(
            anotherClientChain, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_TokensListTooLong() public {
        _prepareInputs(256);

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(ExocoreGatewayStorage.WhitelistTokensListTooLong.selector));
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_LengthNotMatch() public {
        _prepareInputs(2);
        decimals.push(18);

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(ExocoreGatewayStorage.InvalidWhitelistTokensInput.selector));
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_HasZeroAddressToken() public {
        _prepareInputs(1);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));
        decimals[0] = 18;
        tvlLimits[0] = 1e8 ether;
        names[0] = "RestakeToken";
        metaData[0] = "ERC20 LST token";
        _addWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);

        _prepareInputs(2);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));
        tvlLimits[0] = 1e8 ether;
        tvlLimits[1] = 1e8 ether;
        names[0] = "LST-1";
        names[1] = "LST-2";
        metaData[0] = "LST token";
        metaData[1] = "LST token";

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: token cannot be zero address");
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_HasZeroTVMLimit() public {
        _prepareInputs(1);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));
        decimals[0] = 18;
        tvlLimits[0] = 1e8 ether;
        names[0] = "RestakeToken";
        metaData[0] = "ERC20 LST token";
        _addWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);

        tvlLimits[0] = 0;

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: tvl limit should not be zero");
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_HasTokenNotRegisteredBefore() public {
        _prepareInputs(1);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));
        decimals[0] = 18;
        tvlLimits[0] = 1e10 ether;
        names[0] = "RestakeToken";
        metaData[0] = "ERC20 LST token";

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: token has not been added to whitelist before");
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_Success_UpdateWhitelistTokens() public {
        _prepareInputs(1);
        whitelistTokens[0] = bytes32(bytes20(address(restakeToken)));
        decimals[0] = 18;
        tvlLimits[0] = 1e8 ether;
        names[0] = "RestakeToken";
        metaData[0] = "ERC20 LST token";

        // add token to whitelist first
        _addWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);

        // then update token info
        tvlLimits[0] = 1e10 ether;
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit WhitelistTokenUpdated(clientChainId, whitelistTokens[0]);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.updateWhitelistedTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function _prepareInputs(uint256 listLength) internal {
        whitelistTokens = new bytes32[](listLength);
        decimals = new uint8[](listLength);
        tvlLimits = new uint256[](listLength);
        names = new string[](listLength);
        metaData = new string[](listLength);
    }

    function _addWhitelistTokens(
        uint32 clientChainId_,
        bytes32[] memory whitelistTokens_,
        uint8[] memory decimals_,
        uint256[] memory tvlLimits_,
        string[] memory names_,
        string[] memory metaData_
    ) internal {
        vm.startPrank(exocoreValidatorSet.addr);
        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));
        exocoreGateway.addWhitelistTokens{value: nativeFee}(
            clientChainId_, whitelistTokens_, decimals_, tvlLimits_, names_, metaData_
        );
        vm.stopPrank();
    }

}
