pragma solidity ^0.8.19;

import {NonShortCircuitEndpointV2Mock} from "../../mocks/NonShortCircuitEndpointV2Mock.sol";
import "src/interfaces/precompiles/IAssets.sol";

import "src/interfaces/precompiles/IDelegation.sol";
import "src/interfaces/precompiles/IReward.sol";

import "src/libraries/Errors.sol";
import "test/mocks/AssetsMock.sol";

import "test/mocks/DelegationMock.sol";
import "test/mocks/RewardMock.sol";

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
import {Action, GatewayStorage} from "src/storage/GatewayStorage.sol";

contract SetUp is Test {

    using AddressCast for address;

    Player[] players;
    Player exocoreValidatorSet;
    Player deployer;
    Player withdrawer;

    ExocoreGateway exocoreGateway;
    ClientChainGateway clientGateway;
    ClientChainGateway solanaClientGateway;

    NonShortCircuitEndpointV2Mock exocoreLzEndpoint;
    NonShortCircuitEndpointV2Mock clientLzEndpoint;
    NonShortCircuitEndpointV2Mock solanaClientLzEndpoint;

    ERC20 restakeToken;

    uint16 exocoreChainId = 1;
    uint16 clientChainId = 2;
    uint16 solanaClientChainId = 40_168;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    event Paused(address account);
    event Unpaused(address account);
    event ExocorePrecompileError(address indexed precompile, uint64 nonce);
    event MessageSent(Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});
        deployer = Player({privateKey: uint256(0xb), addr: vm.addr(uint256(0xb))});
        withdrawer = Player({privateKey: uint256(0xc), addr: vm.addr(uint256(0xb))});
        clientGateway = ClientChainGateway(payable(address(0xd)));
        solanaClientGateway = ClientChainGateway(payable(address(0xe)));

        // bind precompile mock contracts code to constant precompile address
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("RewardMock.sol");
        vm.etch(REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);

        _deploy();

        vm.deal(exocoreValidatorSet.addr, 100 ether);
        vm.deal(deployer.addr, 100 ether);
    }

    function _deploy() internal {
        vm.startPrank(deployer.addr);

        restakeToken = new ERC20PresetFixedSupply("rest", "rest", 1e34, exocoreValidatorSet.addr);

        exocoreLzEndpoint = new NonShortCircuitEndpointV2Mock(exocoreChainId, exocoreValidatorSet.addr);
        clientLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet.addr);
        solanaClientLzEndpoint = new NonShortCircuitEndpointV2Mock(solanaClientChainId, exocoreValidatorSet.addr);

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

        exocoreLzEndpoint.setDestLzEndpoint(address(solanaClientGateway), address(clientLzEndpoint));
        exocoreGateway.registerOrUpdateClientChain(
            solanaClientChainId,
            address(solanaClientGateway).toBytes32(),
            20,
            "solanaClientChain",
            "Non-EVM compatible client chain",
            "ed25519"
        );

        vm.stopPrank();

        // transfer some gas fee to exocore gateway as it has to pay for the relay fee to layerzero endpoint when
        // sending back response
        deal(address(exocoreGateway), 1e22);
    }

    function generateUID(uint64 nonce, bool fromClientChainToExocore) internal view returns (bytes32 uid) {
        uid = generateUID(nonce, fromClientChainToExocore, true);
    }

    function generateUID(uint64 nonce, bool fromClientChainToExocore, bool isEVM) internal view returns (bytes32 uid) {
        if (fromClientChainToExocore) {
            if (isEVM) {
                uid = GUID.generate(
                    nonce, clientChainId, address(clientGateway), exocoreChainId, address(exocoreGateway).toBytes32()
                );
            } else {
                uid = GUID.generate(
                    nonce,
                    solanaClientChainId,
                    address(solanaClientGateway),
                    exocoreChainId,
                    address(exocoreGateway).toBytes32()
                );
            }
        } else {
            if (isEVM) {
                uid = GUID.generate(
                    nonce, exocoreChainId, address(exocoreGateway), clientChainId, address(clientGateway).toBytes32()
                );
            } else {
                uid = GUID.generate(
                    nonce,
                    exocoreChainId,
                    address(exocoreGateway),
                    solanaClientChainId,
                    address(solanaClientGateway).toBytes32()
                );
            }
        }
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

    event AssociationResult(bool indexed success, bool indexed isAssociate, bytes32 indexed staker);

    function setUp() public override {
        super.setUp();

        // bind precompile mock contracts code to constant precompile address
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory RewardMockCode = vm.getDeployedCode("RewardMock.sol");
        vm.etch(REWARD_PRECOMPILE_ADDRESS, RewardMockCode);
    }

    function test_NotRevert_WithdrawalAmountOverflow() public {
        bytes memory payload = abi.encodePacked(
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(withdrawer.addr))),
            uint256(WITHDRAWAL_AMOUNT)
        );
        bytes memory msg_ = abi.encodePacked(Action.REQUEST_WITHDRAW_LST, payload);

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
        bytes memory msg_ = abi.encodePacked(Action.REQUEST_ASSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit AssociationResult(true, true, bytes32(bytes20(staker.addr)));

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
        bytes memory msg_ = abi.encodePacked(Action.REQUEST_ASSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit AssociationResult(false, true, bytes32(bytes20(staker.addr)));

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
        bytes memory msg_ = abi.encodePacked(Action.REQUEST_ASSOCIATE_OPERATOR, payload);

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
        emit AssociationResult(true, true, bytes32(bytes20(staker.addr)));

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
        bytes memory msg_ = abi.encodePacked(Action.REQUEST_DISSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit AssociationResult(true, false, bytes32(bytes20(staker.addr)));

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
        bytes memory msg_ = abi.encodePacked(Action.REQUEST_DISSOCIATE_OPERATOR, payload);

        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit AssociationResult(false, false, bytes32(bytes20(staker.addr)));

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

    uint256 MESSAGE_LENGTH = 1 + 32 + 16; // action + token address as bytes32 + uint128 tvl limit
    uint256 nativeFee;
    uint256 nativeFeeForSolana;

    error IncorrectNativeFee(uint256 amount);

    event WhitelistTokenAdded(uint32 clientChainId, bytes32 token);

    function setUp() public virtual override {
        super.setUp();
        nativeFee = exocoreGateway.quote(clientChainId, new bytes(MESSAGE_LENGTH));
        bytes memory message = new bytes(MESSAGE_LENGTH);
        message[0] = bytes1(abi.encodePacked(Action.REQUEST_ADD_WHITELIST_TOKEN));
        nativeFeeForSolana = exocoreGateway.quote(solanaClientChainId, message);
    }

    function test_RevertWhen_CallerNotOwner() public {
        vm.startPrank(deployer.addr);
        vm.expectRevert("Ownable: caller is not the owner");
        exocoreGateway.addWhitelistToken{value: nativeFee}(
            clientChainId, bytes32(0), 18, "name", "metadata", "oracleInfo", 0
        );
    }

    function test_RevertWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.pause();
        vm.expectRevert("Pausable: paused");
        exocoreGateway.addWhitelistToken{value: nativeFee}(
            clientChainId, bytes32(0), 18, "name", "metadata", "oracleInfo", 0
        );
    }

    function test_RevertWhen_ZeroValue() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(IncorrectNativeFee.selector, uint256(0)));
        exocoreGateway.addWhitelistToken{value: 0}(
            clientChainId, bytes32(bytes20(address(restakeToken))), 18, "name", "metadata", "oracleInfo", 0
        );
    }

    function test_RevertWhen_HasZeroAddressToken() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: token cannot be zero address");
        exocoreGateway.addWhitelistToken{value: nativeFee}(
            clientChainId, bytes32(0), 18, "name", "metadata", "oracleInfo", 0
        );
    }

    function test_Success_AddWhiteListToken() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(address(exocoreGateway));
        emit WhitelistTokenAdded(clientChainId, bytes32(bytes20(address(restakeToken))));
        vm.expectEmit(address(exocoreGateway));
        emit MessageSent(Action.REQUEST_ADD_WHITELIST_TOKEN, generateUID(1, false), 1, nativeFee);
        exocoreGateway.addWhitelistToken{value: nativeFee}(
            clientChainId,
            bytes32(bytes20(address(restakeToken))),
            18,
            "RestakeToken",
            "ERC20 LST token",
            "oracleInfo",
            5000 * 1e18
        );
        vm.stopPrank();
    }

    function test_Success_AddWhiteListTokenOnSolana() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(address(exocoreGateway));
        emit WhitelistTokenAdded(solanaClientChainId, bytes32(bytes20(address(restakeToken))));
        vm.expectEmit(address(exocoreGateway));
        emit MessageSent(Action.REQUEST_ADD_WHITELIST_TOKEN, generateUID(1, false, false), 1, nativeFeeForSolana);
        exocoreGateway.addWhitelistToken{value: nativeFeeForSolana}(
            solanaClientChainId,
            bytes32(bytes20(address(restakeToken))),
            9,
            "RestakeToken",
            "Spl LST token",
            "oracleInfo",
            5000 * 1e9
        );
        vm.stopPrank();
    }

}

contract UpdateWhitelistTokens is SetUp {

    struct TokenDetails {
        bytes32 tokenAddress;
        uint8 decimals;
        string name;
        string metaData;
        string oracleInfo;
    }

    TokenDetails tokenDetails;

    event WhitelistTokenAdded(uint32 clientChainId, bytes32 token);
    event WhitelistTokenUpdated(uint32 clientChainId, bytes32 token);

    function setUp() public virtual override {
        super.setUp();
        // the below code is intentionally repeated here, instead of inheriting it from AddWhitelistTokens
        // this is done to not conflate the tests of AddWhitelistTokens with UpdateWhitelistTokens
        uint256 MESSAGE_LENGTH = 1 + 32 + 16; // action + token address as bytes32 + uint128
        uint256 nativeFee = exocoreGateway.quote(clientChainId, new bytes(MESSAGE_LENGTH));
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(address(exocoreGateway));
        emit WhitelistTokenAdded(clientChainId, bytes32(bytes20(address(restakeToken))));
        vm.expectEmit(address(exocoreGateway));
        emit MessageSent(Action.REQUEST_ADD_WHITELIST_TOKEN, generateUID(1, false), 1, nativeFee);
        exocoreGateway.addWhitelistToken{value: nativeFee}(
            clientChainId,
            bytes32(bytes20(address(restakeToken))),
            18,
            "RestakeToken",
            "ERC20 LST token",
            "oracleInfo",
            5000 * 1e18
        );
        vm.stopPrank();
        tokenDetails = TokenDetails({
            tokenAddress: bytes32(bytes20(address(restakeToken))),
            decimals: 18,
            name: "RestakeToken",
            metaData: "ERC20 LST token",
            oracleInfo: "oracleInfo"
        });
    }

    function test_RevertUpdateWhen_CallerNotOwner() public {
        vm.startPrank(deployer.addr);
        vm.expectRevert("Ownable: caller is not the owner");
        exocoreGateway.updateWhitelistToken(clientChainId, tokenDetails.tokenAddress, tokenDetails.metaData);
    }

    function test_RevertUpdateWhen_Paused() public {
        vm.startPrank(exocoreValidatorSet.addr);
        exocoreGateway.pause();
        vm.expectRevert("Pausable: paused");
        exocoreGateway.updateWhitelistToken(clientChainId, tokenDetails.tokenAddress, tokenDetails.metaData);
    }

    function test_RevertUpdateWhen_HasZeroAddress() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: token cannot be zero address");
        exocoreGateway.updateWhitelistToken(clientChainId, bytes32(0), tokenDetails.metaData);
    }

    function test_RevertUpdateWhen_HasZeroChainId() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert("ExocoreGateway: client chain id cannot be zero");
        exocoreGateway.updateWhitelistToken(0, tokenDetails.tokenAddress, tokenDetails.metaData);
    }

    function test_Success_UpdateWhitelistToken() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(address(exocoreGateway));
        emit WhitelistTokenUpdated(clientChainId, tokenDetails.tokenAddress);
        exocoreGateway.updateWhitelistToken(clientChainId, tokenDetails.tokenAddress, "new metadata");
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

    uint256 nativeFee;

    error NoPeer(uint32 chainId);

    function setUp() public virtual override {
        super.setUp();
        nativeFee = exocoreGateway.quote(clientChainId, abi.encodePacked(Action.REQUEST_MARK_BOOTSTRAP, ""));
    }

    function test_Success() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectEmit(address(exocoreGateway));
        emit ExocoreGatewayStorage.BootstrapRequestSent(clientChainId);
        exocoreGateway.markBootstrap{value: nativeFee}(clientChainId);
    }

    function test_Fail() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(NoPeer.selector, clientChainId + 1));
        exocoreGateway.markBootstrap{value: nativeFee}(clientChainId + 1);
    }

}
