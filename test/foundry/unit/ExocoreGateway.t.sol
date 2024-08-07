pragma solidity ^0.8.19;

import {NonShortCircuitEndpointV2Mock} from "../../mocks/NonShortCircuitEndpointV2Mock.sol";
import "src/interfaces/precompiles/IAssets.sol";
import "src/interfaces/precompiles/IClaimReward.sol";
import "src/interfaces/precompiles/IDelegation.sol";

import "src/libraries/Errors.sol";
import "test/mocks/AssetsMock.sol";
import "test/mocks/ClaimRewardMock.sol";
import "test/mocks/DelegationMock.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
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
            clientChainId,
            address(clientGateway).toBytes32(),
            20,
            "clientChain",
            "EVM compatible client chain",
            "secp256k1"
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
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        vm.startPrank(deployer.addr);
        exocoreGateway.pause();
    }

    function test_RevertWhen_CallDisabledFunctionsWhenPaused() public {
        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        vm.prank(address(exocoreLzEndpoint));
        vm.expectRevert("Pausable: paused");
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
    string operator = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";

    event AssociateOperatorResult(bool indexed success, bytes32 indexed staker, bytes operator);
    event DissociateOperatorResult(bool indexed success, bytes32 indexed staker);

    function setUp() public override {
        super.setUp();

        // bind precompile mock contracts code to constant precompile address
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);
    }

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

    function test_Success_AssociateOperatorWithStaker() public {
        Player memory staker = players[0];

        bytes memory payload = abi.encodePacked(abi.encodePacked(bytes32(bytes20(staker.addr))), bytes(operator));
        bytes memory msg_ = abi.encodePacked(GatewayStorage.Action.REQUEST_ASSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit AssociateOperatorResult(true, bytes32(bytes20(staker.addr)), bytes(operator));

        vm.prank(address(exocoreLzEndpoint));
        exocoreGateway.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(1)),
            bytes32(0),
            msg_,
            address(0x2),
            bytes("")
        );
    }

    function test_EmitResultAsFailed_StakerAlreadyBeenAssociated() public {
        test_Success_AssociateOperatorWithStaker();

        Player memory staker = players[0];
        string memory anotherOperator = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f811111";

        bytes memory payload = abi.encodePacked(abi.encodePacked(bytes32(bytes20(staker.addr))), bytes(anotherOperator));
        bytes memory msg_ = abi.encodePacked(GatewayStorage.Action.REQUEST_ASSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit AssociateOperatorResult(false, bytes32(bytes20(staker.addr)), bytes(anotherOperator));

        vm.prank(address(exocoreLzEndpoint));
        exocoreGateway.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(2)),
            bytes32(0),
            msg_,
            address(0x2),
            bytes("")
        );

        bytes memory associatedOperator = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getAssociatedOperator(
            clientChainId, abi.encodePacked(bytes32(bytes20(staker.addr)))
        );
        assertEq(keccak256(associatedOperator), keccak256(bytes(operator)));
    }

    function test_EmitResultAsSuccess_AssociateStakerOnAnotherChain() public {
        test_Success_AssociateOperatorWithStaker();

        Player memory staker = players[0];
        string memory anotherOperator = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f811111";
        uint32 anotherChainId = 123;

        bytes memory payload = abi.encodePacked(abi.encodePacked(bytes32(bytes20(staker.addr))), bytes(anotherOperator));
        bytes memory msg_ = abi.encodePacked(GatewayStorage.Action.REQUEST_ASSOCIATE_OPERATOR, payload);

        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherChainId,
            address(clientGateway).toBytes32(),
            20,
            "clientChain",
            "EVM compatible client chain",
            "secp256k1"
        );
        vm.stopPrank();

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit AssociateOperatorResult(true, bytes32(bytes20(staker.addr)), bytes(anotherOperator));

        vm.prank(address(exocoreLzEndpoint));
        exocoreGateway.lzReceive(
            Origin(anotherChainId, address(clientGateway).toBytes32(), uint64(1)),
            bytes32(0),
            msg_,
            address(0x2),
            bytes("")
        );

        bytes memory associatedOperator = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getAssociatedOperator(
            anotherChainId, abi.encodePacked(bytes32(bytes20(staker.addr)))
        );
        assertEq(keccak256(associatedOperator), keccak256(bytes(anotherOperator)));
    }

    function test_Success_DissociateOperatorFromStaker() public {
        test_Success_AssociateOperatorWithStaker();

        Player memory staker = players[0];

        bytes memory payload = abi.encodePacked(abi.encodePacked(bytes32(bytes20(staker.addr))));
        bytes memory msg_ = abi.encodePacked(GatewayStorage.Action.REQUEST_DISSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit DissociateOperatorResult(true, bytes32(bytes20(staker.addr)));

        vm.prank(address(exocoreLzEndpoint));
        exocoreGateway.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(2)),
            bytes32(0),
            msg_,
            address(0x2),
            bytes("")
        );
    }

    function test_EmitResultAsFailed_DissociateFreshStaker() public {
        Player memory staker = players[0];

        bytes memory payload = abi.encodePacked(abi.encodePacked(bytes32(bytes20(staker.addr))));
        bytes memory msg_ = abi.encodePacked(GatewayStorage.Action.REQUEST_DISSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit DissociateOperatorResult(false, bytes32(bytes20(staker.addr)));

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

contract RegisterOrUpdateClientChain is SetUp {

    using AddressCast for address;

    event ClientChainRegistered(uint32 clientChainId);
    event ClientChainUpdated(uint32 clientChainId);

    uint32 anotherClientChain;
    bytes32 peer;
    uint8 addressLength;
    string name;
    string metaInfo;
    string signatureType;

    function test_Success_RegisterClientChain() public {
        _prepareClientChainData();

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit ClientChainRegistered(anotherClientChain);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_Success_UpdateClientChain() public {
        test_Success_RegisterClientChain();

        peer = bytes32(uint256(321));
        metaInfo = "Testnet";

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit ClientChainUpdated(anotherClientChain);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_RevertWhen_CallerNotOwner() public {
        _prepareClientChainData();

        vm.startPrank(deployer.addr);
        vm.expectRevert("Ownable: caller is not the owner");
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        _prepareClientChainData();

        vm.expectRevert("Pausable: paused");
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_RevertWhen_ZeroOrEmptyClientChain() public {
        _prepareClientChainData();
        anotherClientChain = 0;

        vm.expectRevert(Errors.ZeroValue.selector);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_RevertWhen_ZeroOrEmptyPeer() public {
        _prepareClientChainData();
        peer = bytes32(0);

        vm.expectRevert(Errors.ZeroValue.selector);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_RevertWhen_ZeroOrEmptyAddressLength() public {
        _prepareClientChainData();
        addressLength = 0;

        vm.expectRevert(Errors.ZeroValue.selector);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_RevertWhen_EmptyName() public {
        _prepareClientChainData();
        name = "";

        vm.expectRevert(Errors.ZeroValue.selector);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function test_RevertWhen_EmptyMetaInfo() public {
        _prepareClientChainData();
        metaInfo = "";

        vm.expectRevert(Errors.ZeroValue.selector);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, peer, addressLength, name, metaInfo, signatureType
        );
    }

    function _prepareClientChainData() internal {
        anotherClientChain = clientChainId + 1;
        peer = bytes32(uint256(123));
        addressLength = 20;
        name = "AnotherClientChain";
        metaInfo = "EVM compatible client chain";
        signatureType = "secp256k1";
    }

}

contract SetPeer is SetUp {

    ExocoreGateway gateway;

    uint32 anotherClientChain = clientChainId + 1;
    bytes32 anotherPeer = bytes32("0xabcdef");
    bytes32 newPeer = bytes32("0x123");

    event PeerSet(uint32 eid, bytes32 peer);

    function test_Success_SetPeer() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit PeerSet(anotherClientChain, anotherPeer);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, anotherPeer, 20, "Test Chain", "Test Meta", "ECDSA"
        );

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit PeerSet(anotherClientChain, newPeer);
        exocoreGateway.setPeer(anotherClientChain, newPeer);
    }

    function test_RevertWhen_CallerNotOwner() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit PeerSet(anotherClientChain, anotherPeer);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChain, anotherPeer, 20, "Test Chain", "Test Meta", "ECDSA"
        );
        vm.stopPrank();

        vm.startPrank(deployer.addr);
        vm.expectRevert("Ownable: caller is not the owner");
        exocoreGateway.setPeer(anotherClientChain, newPeer);
    }

    function test_RevertWhen_ClientChainNotRegistered() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(Errors.ExocoreGatewayNotRegisteredClientChainId.selector);
        exocoreGateway.setPeer(anotherClientChain, newPeer);
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
        vm.expectRevert("Ownable: caller is not the owner");
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        _prepareInputs(2);

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));
        vm.expectRevert("Pausable: paused");
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );
    }

    function test_RevertWhen_TokensListTooLong() public {
        _prepareInputs(256);

        uint256 messageLength = TOKEN_ADDRESS_BYTES_LENGTH * whitelistTokens.length + 2;
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(messageLength));

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(ExocoreGatewayStorage.WhitelistTokensListTooLong.selector));
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
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
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
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
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
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
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
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
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
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
        vm.expectRevert("Ownable: caller is not the owner");
        exocoreGateway.addOrUpdateWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.pause();

        _prepareInputs(2);

        vm.expectRevert("Pausable: paused");
        exocoreGateway.addOrUpdateWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_TokensListTooLong() public {
        _prepareInputs(256);

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(ExocoreGatewayStorage.WhitelistTokensListTooLong.selector));
        exocoreGateway.addOrUpdateWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
    }

    function test_RevertWhen_LengthNotMatch() public {
        _prepareInputs(2);
        decimals.push(18);

        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(ExocoreGatewayStorage.InvalidWhitelistTokensInput.selector));
        exocoreGateway.addOrUpdateWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
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
        exocoreGateway.addOrUpdateWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
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
        exocoreGateway.addOrUpdateWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
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
        exocoreGateway.addOrUpdateWhitelistTokens(clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData);
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
        exocoreGateway.addOrUpdateWhitelistTokens{value: nativeFee}(
            clientChainId_, whitelistTokens_, decimals_, tvlLimits_, names_, metaData_
        );
        vm.stopPrank();
    }

}

contract AssociateOperatorWithEVMStaker is SetUp {

    using AddressCast for address;

    string operator = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
    string anotherOperator = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f811111";
    uint32 anotherChainId = 123;

    function test_Success_AssociateEVMStaker() public {
        Player memory staker = players[0];
        vm.startPrank(staker.addr);
        exocoreGateway.associateOperatorWithEVMStaker(clientChainId, operator);

        bytes memory associatedOperator = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getAssociatedOperator(
            clientChainId, abi.encodePacked(bytes32(bytes20(staker.addr)))
        );
        assertEq(keccak256(associatedOperator), keccak256(bytes(operator)));
    }

    function test_RevertWhen_ClientChainNotRegistered() public {
        Player memory staker = players[0];
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AssociateOperatorFailed.selector, anotherChainId, staker.addr, operator)
        );
        vm.startPrank(staker.addr);
        exocoreGateway.associateOperatorWithEVMStaker(anotherChainId, operator);
    }

    function test_RevertWhen_AssociateMarkedStaker() public {
        test_Success_AssociateEVMStaker();

        Player memory staker = players[0];
        vm.expectRevert(
            abi.encodeWithSelector(Errors.AssociateOperatorFailed.selector, clientChainId, staker.addr, anotherOperator)
        );
        vm.startPrank(staker.addr);
        exocoreGateway.associateOperatorWithEVMStaker(clientChainId, anotherOperator);
    }

    function test_Success_AssociateSameStakerButAnotherChain() public {
        test_Success_AssociateEVMStaker();

        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherChainId,
            address(clientGateway).toBytes32(),
            20,
            "clientChain",
            "EVM compatible client chain",
            "secp256k1"
        );
        vm.stopPrank();

        Player memory staker = players[0];
        vm.startPrank(staker.addr);
        exocoreGateway.associateOperatorWithEVMStaker(anotherChainId, anotherOperator);

        bytes memory associatedOperator = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getAssociatedOperator(
            clientChainId, abi.encodePacked(bytes32(bytes20(staker.addr)))
        );
        assertEq(keccak256(associatedOperator), keccak256(bytes(operator)));
        associatedOperator = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getAssociatedOperator(
            anotherChainId, abi.encodePacked(bytes32(bytes20(staker.addr)))
        );
        assertEq(keccak256(associatedOperator), keccak256(bytes(anotherOperator)));
    }

    function test_Success_DissociateEVMStaker() public {
        test_Success_AssociateEVMStaker();

        Player memory staker = players[0];
        vm.startPrank(staker.addr);
        exocoreGateway.dissociateOperatorFromEVMStaker(clientChainId);

        bytes memory associatedOperator = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getAssociatedOperator(
            clientChainId, abi.encodePacked(bytes32(bytes20(staker.addr)))
        );
        assertEq(associatedOperator.length, 0);
    }

    function test_RevertWhen_DissociateClientChainNotRegistered() public {
        Player memory staker = players[0];
        vm.expectRevert(abi.encodeWithSelector(Errors.DissociateOperatorFailed.selector, anotherChainId, staker.addr));
        vm.startPrank(staker.addr);
        exocoreGateway.dissociateOperatorFromEVMStaker(anotherChainId);
    }

    function test_RevertWhen_DissociatePureStaker() public {
        Player memory staker = players[0];
        vm.expectRevert(abi.encodeWithSelector(Errors.DissociateOperatorFailed.selector, clientChainId, staker.addr));
        vm.startPrank(staker.addr);
        exocoreGateway.dissociateOperatorFromEVMStaker(clientChainId);
    }

}

contract MarkBootstrap is SetUp {

    uint32 anotherClientChainId = clientChainId;

    function test_Setup() public {
        assertEq(exocoreGateway.chainToBootstrapped(clientChainId), false);
    }

    function test_Success() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(address(exocoreGateway));
        emit ExocoreGatewayStorage.BootstrapRequestSent(clientChainId);
        exocoreGateway.markBootstrapOnAllChains();
        assertEq(exocoreGateway.chainToBootstrapped(clientChainId), true);
    }

    function test_Success_Multiple() public {
        _registerClientChain();
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(address(exocoreGateway));
        emit ExocoreGatewayStorage.BootstrapRequestSent(clientChainId);
        vm.expectEmit(address(exocoreGateway));
        emit ExocoreGatewayStorage.BootstrapRequestSent(anotherClientChainId);
        assertEq(exocoreGateway.chainToBootstrapped(clientChainId), false);
        assertEq(exocoreGateway.chainToBootstrapped(anotherClientChainId), false);
        exocoreGateway.markBootstrapOnAllChains();
        assertEq(exocoreGateway.chainToBootstrapped(clientChainId), true);
        assertEq(exocoreGateway.chainToBootstrapped(anotherClientChainId), true);
    }

    function _registerClientChain() internal {
        // actual registration of chain
        anotherClientChainId += 1;
        bytes32 peer = bytes32(uint256(123));
        uint8 addressLength = 20;
        string memory name = "AnotherClientChain";
        string memory metaInfo = "EVM compatible client chain";
        string memory signatureType = "secp256k1";
        // but first, set the lz thing up
        exocoreLzEndpoint.setDestLzEndpoint(address(123), /* peer */ address(clientLzEndpoint));
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit ExocoreGatewayStorage.ClientChainRegistered(anotherClientChainId);
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.registerOrUpdateClientChain(
            anotherClientChainId, peer, addressLength, name, metaInfo, signatureType
        );
    }

}
