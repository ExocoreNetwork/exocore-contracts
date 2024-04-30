pragma solidity ^0.8.19;

import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";
import "@openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

import "../../src/core/ClientChainGateway.sol";
import {Vault} from "../../src/core/Vault.sol";
import "../../src/core/ExoCapsule.sol";
import "../../src/core/ExocoreGateway.sol";
import {NonShortCircuitEndpointV2Mock} from "../mocks/NonShortCircuitEndpointV2Mock.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/interfaces/precompiles/IDeposit.sol";
import "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../../src/interfaces/precompiles/IClaimReward.sol";
import "test/mocks/ETHPOSDepositMock.sol";
import "src/core/ExoCapsule.sol";

contract ExocoreDeployer is Test {
    using AddressCast for address;

    Player[] players;
    address[] whitelistTokens;
    Player exocoreValidatorSet;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    Vault vault;
    ExocoreGateway exocoreGateway;
    ILayerZeroEndpointV2 clientChainLzEndpoint;
    ILayerZeroEndpointV2 exocoreLzEndpoint;
    IBeaconChainOracle beaconOracle;
    IVault vaultImplementation;
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon capsuleBeacon;

    IETHPOSDeposit constant ETH_POS = IETHPOSDeposit(0x00000000219ab540356cBB839Cbe05303d7705Fa);

    bytes32[] validatorContainer;
    bytes32 beaconBlockRoot;
    IExoCapsule.ValidatorContainerProof validatorProof;

    uint32 exocoreChainId = 2;
    uint32 clientChainId = 1;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});

        // load beacon chain validator container and proof from json file
        _loadValidatorContainer();
        _loadValidatorProof();
        _loadBeaconBlockRoot;

        vm.chainId(clientChainId);
        _deploy();
    }

    function _loadValidatorContainer() internal {
        string memory validatorInfo = vm.readFile("test/foundry/test-data/validator_container_proof_302913.json");

        validatorContainer = stdJson.readBytes32Array(validatorInfo, ".ValidatorFields");
        require(validatorContainer.length > 0, "validator container should not be empty");
    }

    function _loadValidatorProof() internal {
        string memory validatorInfo = vm.readFile("test/foundry/test-data/validator_container_proof_302913.json");

        validatorProof.stateRoot = stdJson.readBytes32(validatorInfo, ".beaconStateRoot");
        require(validatorProof.stateRoot != bytes32(0), "state root should not be empty");
        validatorProof.stateRootProof = stdJson.readBytes32Array(validatorInfo, ".StateRootAgainstLatestBlockHeaderProof");
        require(validatorProof.stateRootProof.length == 3, "state root proof should have 3 nodes");
        validatorProof.validatorContainerRootProof = stdJson.readBytes32Array(validatorInfo, ".WithdrawalCredentialProof");
        require(validatorProof.validatorContainerRootProof.length == 46, "validator root proof should have 46 nodes");
        validatorProof.validatorIndex = stdJson.readUint(validatorInfo, ".validatorIndex");
        require(validatorProof.validatorIndex != 0, "validator root index should not be 0");
    }

    function _loadBeaconBlockRoot() internal {
        string memory validatorInfo = vm.readFile("test/foundry/test-data/validator_container_proof_302913.json");

        beaconBlockRoot = stdJson.readBytes32(validatorInfo, ".latestBlockHeaderRoot");
        require(beaconBlockRoot != bytes32(0), "beacon block root should not be empty");
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

        // attach ETHPOSDepositMock contract code to constant address
        ETHPOSDepositMock ethPOSDepositMock = new ETHPOSDepositMock();
        vm.etch(address(ETH_POS), address(ethPOSDepositMock).code);

        // deploy and initialize client chain contracts
        whitelistTokens.push(address(restakeToken));
        
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(beaconOracle),
            address(vaultBeacon),
            address(capsuleBeacon)
        );
        clientGateway = ClientChainGateway(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(clientGatewayLogic),
                        address(proxyAdmin),
                        abi.encodeWithSelector(
                            clientGatewayLogic.initialize.selector,
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens
                        )
                    )
                )
            )
        );

        // find vault according to uderlying token address
        vault = Vault(address(clientGateway.tokenVaults(address(restakeToken))));

        // deploy Exocore network contracts
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway(address(exocoreLzEndpoint));
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

        // as LzReceivers, gateway should set bytes(sourceChainGatewayAddress+thisAddress) as trusted remote to receive messages
        clientGateway.setPeer(exocoreChainId, address(exocoreGateway).toBytes32());
        exocoreGateway.setPeer(clientChainId, address(clientGateway).toBytes32());
        vm.stopPrank();

        // bind precompile mock contracts code to constant precompile address
        bytes memory DepositMockCode = vm.getDeployedCode("DepositMock.sol");
        vm.etch(DEPOSIT_PRECOMPILE_ADDRESS, DepositMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawPrincipleMockCode = vm.getDeployedCode("WithdrawPrincipleMock.sol");
        vm.etch(WITHDRAW_PRECOMPILE_ADDRESS, WithdrawPrincipleMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);
    }

    function _deployBeaconOracle() internal returns (address) {
        uint256 GENESIS_BLOCK_TIMESTAMP;

        if (block.chainid == 1) {
            GENESIS_BLOCK_TIMESTAMP = 1606824023;
        } else if (block.chainid == 5) {
            GENESIS_BLOCK_TIMESTAMP = 1616508000;
        } else if (block.chainid == 11155111) {
            GENESIS_BLOCK_TIMESTAMP = 1655733600;
        } else if (block.chainid == 17000) {
            GENESIS_BLOCK_TIMESTAMP = 1695902400;
        } else {
            revert("Unsupported chainId.");
        }

        EigenLayerBeaconOracle oracle = new EigenLayerBeaconOracle(GENESIS_BLOCK_TIMESTAMP);
        return address(oracle);
    }
}
