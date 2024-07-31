pragma solidity ^0.8.19;

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/core/ClientChainGateway.sol";

import "../../src/core/ExoCapsule.sol";
import "../../src/core/ExocoreGateway.sol";
import {Vault} from "../../src/core/Vault.sol";
import "src/storage/GatewayStorage.sol";

import {IVault} from "../../src/interfaces/IVault.sol";

import "../../src/interfaces/precompiles/IAssets.sol";
import "../../src/interfaces/precompiles/IClaimReward.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";

import "../mocks/AssetsMock.sol";
import "../mocks/ClaimRewardMock.sol";
import "../mocks/DelegationMock.sol";
import {NonShortCircuitEndpointV2Mock} from "../mocks/NonShortCircuitEndpointV2Mock.sol";

import "src/core/BeaconProxyBytecode.sol";
import "src/core/ExoCapsule.sol";

import "src/libraries/BeaconChainProofs.sol";
import "src/libraries/Endian.sol";
import "test/mocks/ETHPOSDepositMock.sol";

contract ExocoreDeployer is Test {

    using AddressCast for address;
    using Endian for bytes32;

    Player[] players;
    bytes32[] whitelistTokens;
    Player exocoreValidatorSet;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    ClientChainGateway clientGatewayLogic;
    Vault vault;
    ExoCapsule capsule;
    ExocoreGateway exocoreGateway;
    ExocoreGateway exocoreGatewayLogic;
    ILayerZeroEndpointV2 clientChainLzEndpoint;
    ILayerZeroEndpointV2 exocoreLzEndpoint;
    IBeaconChainOracle beaconOracle;
    IVault vaultImplementation;
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon capsuleBeacon;
    BeaconProxyBytecode beaconProxyBytecode;

    uint256 constant BEACON_CHAIN_GENESIS_TIME = 1_606_824_023;
    /// @notice The number of slots each epoch in the beacon chain
    uint64 internal constant SLOTS_PER_EPOCH = 32;
    /// @notice The number of seconds in a slot in the beacon chain
    uint64 internal constant SECONDS_PER_SLOT = 12;
    /// @notice Number of seconds per epoch: 384 == 32 slots/epoch * 12 seconds/slot
    uint64 internal constant SECONDS_PER_EPOCH = SLOTS_PER_EPOCH * SECONDS_PER_SLOT;
    uint256 internal constant VERIFY_BALANCE_UPDATE_WINDOW_SECONDS = 4.5 hours;
    uint256 constant GWEI_TO_WEI = 1e9;
    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    IETHPOSDeposit constant ETH_POS = IETHPOSDeposit(0x00000000219ab540356cBB839Cbe05303d7705Fa);
    bytes constant BEACON_PROXY_BYTECODE =
        hex"608060405260405161090e38038061090e83398101604081905261002291610460565b61002e82826000610035565b505061058a565b61003e83610100565b6040516001600160a01b038416907f1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e90600090a260008251118061007f5750805b156100fb576100f9836001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100c5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100e99190610520565b836102a360201b6100291760201c565b505b505050565b610113816102cf60201b6100551760201c565b6101725760405162461bcd60e51b815260206004820152602560248201527f455243313936373a206e657720626561636f6e206973206e6f74206120636f6e6044820152641d1c9858dd60da1b60648201526084015b60405180910390fd5b6101e6816001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101b3573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d79190610520565b6102cf60201b6100551760201c565b61024b5760405162461bcd60e51b815260206004820152603060248201527f455243313936373a20626561636f6e20696d706c656d656e746174696f6e206960448201526f1cc81b9bdd08184818dbdb9d1c9858dd60821b6064820152608401610169565b806102827fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d5060001b6102de60201b6100641760201c565b80546001600160a01b0319166001600160a01b039290921691909117905550565b60606102c883836040518060600160405280602781526020016108e7602791396102e1565b9392505050565b6001600160a01b03163b151590565b90565b6060600080856001600160a01b0316856040516102fe919061053b565b600060405180830381855af49150503d8060008114610339576040519150601f19603f3d011682016040523d82523d6000602084013e61033e565b606091505b5090925090506103508683838761035a565b9695505050505050565b606083156103c65782516103bf576001600160a01b0385163b6103bf5760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610169565b50816103d0565b6103d083836103d8565b949350505050565b8151156103e85781518083602001fd5b8060405162461bcd60e51b81526004016101699190610557565b80516001600160a01b038116811461041957600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561044f578181015183820152602001610437565b838111156100f95750506000910152565b6000806040838503121561047357600080fd5b61047c83610402565b60208401519092506001600160401b038082111561049957600080fd5b818501915085601f8301126104ad57600080fd5b8151818111156104bf576104bf61041e565b604051601f8201601f19908116603f011681019083821181831017156104e7576104e761041e565b8160405282815288602084870101111561050057600080fd5b610511836020830160208801610434565b80955050505050509250929050565b60006020828403121561053257600080fd5b6102c882610402565b6000825161054d818460208701610434565b9190910192915050565b6020815260008251806020840152610576816040850160208701610434565b601f01601f19169190910160400192915050565b61034e806105996000396000f3fe60806040523661001357610011610017565b005b6100115b610027610022610067565b610100565b565b606061004e83836040518060600160405280602781526020016102f260279139610124565b9392505050565b6001600160a01b03163b151590565b90565b600061009a7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50546001600160a01b031690565b6001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100fb9190610249565b905090565b3660008037600080366000845af43d6000803e80801561011f573d6000f35b3d6000fd5b6060600080856001600160a01b03168560405161014191906102a2565b600060405180830381855af49150503d806000811461017c576040519150601f19603f3d011682016040523d82523d6000602084013e610181565b606091505b50915091506101928683838761019c565b9695505050505050565b6060831561020d578251610206576001600160a01b0385163b6102065760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064015b60405180910390fd5b5081610217565b610217838361021f565b949350505050565b81511561022f5781518083602001fd5b8060405162461bcd60e51b81526004016101fd91906102be565b60006020828403121561025b57600080fd5b81516001600160a01b038116811461004e57600080fd5b60005b8381101561028d578181015183820152602001610275565b8381111561029c576000848401525b50505050565b600082516102b4818460208701610272565b9190910192915050565b60208152600082518060208401526102dd816040850160208701610272565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a2646970667358221220d51e81d3bc5ed20a26aeb05dce7e825c503b2061aa78628027300c8d65b9d89a64736f6c634300080c0033416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";

    bytes32[] validatorContainer;
    bytes32 beaconBlockRoot; // latest beacon block root
    IExoCapsule.ValidatorContainerProof validatorProof;

    bytes32[] withdrawalContainer;
    BeaconChainProofs.WithdrawalProof withdrawalProof;
    bytes32 withdrawBeaconBlockRoot; // block root for withdrawal proof

    uint256 mockProofTimestamp;
    uint256 mockCurrentBlockTimestamp;
    uint256 activationTimestamp;

    uint32 exocoreChainId = 2;
    uint32 clientChainId = 1;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    event MessageSent(GatewayStorage.Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);
    event NewPacket(uint32, address, bytes32, uint64, bytes);
    event WhitelistTokenAdded(address _token);
    event VaultCreated(address underlyingToken, address vault);
    event RequestFinished(GatewayStorage.Action indexed action, uint64 indexed requestId, bool indexed success);

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});

        // bind precompile mock contracts code to constant precompile address
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);

        // load beacon chain validator container and proof from json file
        string memory validatorInfo = vm.readFile("test/foundry/test-data/validator_container_proof_302913.json");
        _loadValidatorContainer(validatorInfo);

        vm.chainId(clientChainId);
        _deploy();
    }

    function test_AddWhitelistTokens() public {
        // transfer some gas fee to the owner / deployer
        deal(exocoreValidatorSet.addr, 1e22);

        uint8[] memory decimals = new uint8[](2);
        uint256[] memory tvlLimits = new uint256[](2);
        string[] memory names = new string[](2);
        string[] memory metaData = new string[](2);

        whitelistTokens.push(bytes32(bytes20(address(restakeToken))));
        decimals[0] = 18;
        tvlLimits[0] = 1e8 ether;
        names[0] = "RestakeToken";
        metaData[0] = "ERC20 LST token";

        whitelistTokens.push(bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)));
        decimals[1] = 18;
        tvlLimits[1] = 1e8 ether;
        names[1] = "NativeStakedETH";
        metaData[1] = "natively staked ETH on Ethereum";

        // -- add whitelist tokens workflow test --

        vm.startPrank(exocoreValidatorSet.addr);

        // first user call exocore gateway to add whitelist tokens

        // estimate l0 relay fee that the user should pay
        bytes memory registerTokensRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_ADD_WHITELIST_TOKENS,
            uint8(whitelistTokens.length),
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS))
        );
        uint256 registerTokensRequestNativeFee = clientGateway.quote(registerTokensRequestPayload);
        bytes32 registerTokensRequestId = generateUID(1, false);

        // exocore layerzero endpoint should emit the message packet including whitelist tokens payload.
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(1),
            registerTokensRequestPayload
        );
        // exocore gateway gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_ADD_WHITELIST_TOKENS,
            registerTokensRequestId,
            uint64(1),
            registerTokensRequestNativeFee
        );
        exocoreGateway.addOrUpdateWhitelistTokens{value: registerTokensRequestNativeFee}(
            clientChainId, whitelistTokens, decimals, tvlLimits, names, metaData
        );

        // second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        address expectedVault = Create2.computeAddress(
            bytes32(uint256(uint160(address(restakeToken)))),
            keccak256(abi.encodePacked(BEACON_PROXY_BYTECODE, abi.encode(address(vaultBeacon), ""))),
            address(clientGateway)
        );
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit VaultCreated(address(restakeToken), expectedVault);
        emit WhitelistTokenAdded(address(restakeToken));
        emit WhitelistTokenAdded(VIRTUAL_STAKED_ETH_ADDRESS);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), uint64(1)),
            address(clientGateway),
            registerTokensRequestId,
            registerTokensRequestPayload,
            bytes("")
        );

        // find vault according to uderlying token address
        vault = Vault(address(clientGateway.tokenToVault(address(restakeToken))));
        assertEq(address(vault), expectedVault);
        assertTrue(clientGateway.isWhitelistedToken(address(restakeToken)));
        assertTrue(clientGateway.isWhitelistedToken(VIRTUAL_STAKED_ETH_ADDRESS));

        vm.stopPrank();
    }

    function _loadValidatorContainer(string memory validatorInfo) internal {
        validatorContainer = stdJson.readBytes32Array(validatorInfo, ".ValidatorFields");
        require(validatorContainer.length > 0, "validator container should not be empty");

        validatorProof.stateRoot = stdJson.readBytes32(validatorInfo, ".beaconStateRoot");
        require(validatorProof.stateRoot != bytes32(0), "state root should not be empty");
        validatorProof.stateRootProof =
            stdJson.readBytes32Array(validatorInfo, ".StateRootAgainstLatestBlockHeaderProof");
        require(validatorProof.stateRootProof.length == 3, "state root proof should have 3 nodes");
        validatorProof.validatorContainerRootProof =
            stdJson.readBytes32Array(validatorInfo, ".WithdrawalCredentialProof");
        require(validatorProof.validatorContainerRootProof.length == 46, "validator root proof should have 46 nodes");
        validatorProof.validatorIndex = stdJson.readUint(validatorInfo, ".validatorIndex");
        require(validatorProof.validatorIndex != 0, "validator root index should not be 0");

        beaconBlockRoot = stdJson.readBytes32(validatorInfo, ".latestBlockHeaderRoot");
        require(beaconBlockRoot != bytes32(0), "beacon block root should not be empty");
    }

    function _loadWithdrawalContainer(string memory withdrawalInfo) internal {
        withdrawalContainer = stdJson.readBytes32Array(withdrawalInfo, ".WithdrawalFields");
        require(withdrawalContainer.length > 0, "validator container should not be empty");

        // bytes32 array proof data
        withdrawalProof.withdrawalContainerRootProof = stdJson.readBytes32Array(withdrawalInfo, ".WithdrawalProof");
        withdrawalProof.slotProof = stdJson.readBytes32Array(withdrawalInfo, ".SlotProof");
        withdrawalProof.executionPayloadRootProof = stdJson.readBytes32Array(withdrawalInfo, ".ExecutionPayloadProof");
        withdrawalProof.timestampProof = stdJson.readBytes32Array(withdrawalInfo, ".TimestampProof");
        withdrawalProof.historicalSummaryBlockRootProof =
            stdJson.readBytes32Array(withdrawalInfo, ".HistoricalSummaryProof");

        // Index data
        withdrawalProof.blockRootIndex = stdJson.readUint(withdrawalInfo, ".blockHeaderRootIndex");
        require(withdrawalProof.blockRootIndex != 0, "block header root index should not be 0");

        withdrawalProof.historicalSummaryIndex = stdJson.readUint(withdrawalInfo, ".historicalSummaryIndex");
        require(withdrawalProof.historicalSummaryIndex != 0, "historical summary index should not be 0");

        withdrawalProof.withdrawalIndex = stdJson.readUint(withdrawalInfo, ".withdrawalIndex");

        // Root data
        withdrawalProof.blockRoot = stdJson.readBytes32(withdrawalInfo, ".blockHeaderRoot");
        withdrawalProof.slotRoot = stdJson.readBytes32(withdrawalInfo, ".slotRoot");
        withdrawalProof.timestampRoot = stdJson.readBytes32(withdrawalInfo, ".timestampRoot");
        withdrawalProof.executionPayloadRoot = stdJson.readBytes32(withdrawalInfo, ".executionPayloadRoot");
        withdrawalProof.stateRoot = stdJson.readBytes32(withdrawalInfo, ".beaconStateRoot");
        require(withdrawalProof.stateRoot != bytes32(0), "state root should not be empty");
    }

    function _deploy() internal {
        // prepare outside contracts like ERC20 token contract and layerzero endpoint contract
        restakeToken = new ERC20PresetFixedSupply("rest", "rest", 1e34, exocoreValidatorSet.addr);
        clientChainLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet.addr);
        exocoreLzEndpoint = new NonShortCircuitEndpointV2Mock(exocoreChainId, exocoreValidatorSet.addr);
        beaconOracle = IBeaconChainOracle(_deployBeaconOracle());

        // deploy vault implementation contract and capsule implementation contract
        // that has logics called by proxy
        vaultImplementation = new Vault();
        capsuleImplementation = new ExoCapsule();

        // deploy the vault beacon and capsule beacon that store the implementation contract address
        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));

        // deploy BeaconProxyBytecode to store BeaconProxyBytecode
        beaconProxyBytecode = new BeaconProxyBytecode();

        // attach ETHPOSDepositMock contract code to constant address
        ETHPOSDepositMock ethPOSDepositMock = new ETHPOSDepositMock();
        vm.etch(address(ETH_POS), address(ethPOSDepositMock).code);

        // deploy and initialize client chain contracts

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
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(clientGatewayLogic),
                        address(proxyAdmin),
                        abi.encodeWithSelector(
                            clientGatewayLogic.initialize.selector, payable(exocoreValidatorSet.addr)
                        )
                    )
                )
            )
        );

        // deploy Exocore network contracts
        exocoreGatewayLogic = new ExocoreGateway(address(exocoreLzEndpoint));
        exocoreGateway = ExocoreGateway(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(exocoreGatewayLogic),
                        address(proxyAdmin),
                        abi.encodeWithSelector(
                            exocoreGatewayLogic.initialize.selector, payable(exocoreValidatorSet.addr)
                        )
                    )
                )
            )
        );

        // set the destination endpoint for corresponding destinations in endpoint mock
        NonShortCircuitEndpointV2Mock(address(clientChainLzEndpoint)).setDestLzEndpoint(
            address(exocoreGateway), address(exocoreLzEndpoint)
        );
        NonShortCircuitEndpointV2Mock(address(exocoreLzEndpoint)).setDestLzEndpoint(
            address(clientGateway), address(clientChainLzEndpoint)
        );

        // Exocore validator set should be the owner of gateway contracts and only owner could call these functions.
        vm.startPrank(exocoreValidatorSet.addr);

        // as LzReceivers, gateway should set bytes(sourceChainGatewayAddress+thisAddress) as trusted remote to receive
        // messages. On Exocore side, this is done by calling registerClientChain
        clientGateway.setPeer(exocoreChainId, address(exocoreGateway).toBytes32());
        exocoreGateway.registerOrUpdateClientChain(
            clientChainId,
            address(clientGateway).toBytes32(),
            20,
            "clientChain",
            "EVM compatible client chain",
            "secp256k1"
        );
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

    function _getCapsuleFromWithdrawalCredentials(bytes32 withdrawalCredentials) internal pure returns (address) {
        return address(bytes20(uint160(uint256(withdrawalCredentials))));
    }

    function _getPubkey(bytes32[] storage vc) internal view returns (bytes32) {
        return vc[0];
    }

    function _getWithdrawalCredentials(bytes32[] storage vc) internal view returns (bytes32) {
        return vc[1];
    }

    function _getActivationEpoch(bytes32[] storage vc) internal view returns (uint64) {
        return vc[5].fromLittleEndianUint64();
    }

    function _getExitEpoch(bytes32[] storage vc) internal view returns (uint64) {
        return vc[6].fromLittleEndianUint64();
    }

    function _getEffectiveBalance(bytes32[] storage vc) internal view returns (uint64) {
        return vc[2].fromLittleEndianUint64();
    }

    function _getWithdrawalAmount(bytes32[] storage wc) internal view returns (uint64) {
        return wc[3].fromLittleEndianUint64();
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
