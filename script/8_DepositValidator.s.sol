pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/interfaces/IClientChainGateway.sol";
import "../src/interfaces/IVault.sol";
import "../src/interfaces/IExocoreGateway.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../src/interfaces/precompiles/IClaimReward.sol";
import "../src/storage/GatewayStorage.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "../src/core/ExoCapsule.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "src/libraries/Endian.sol";

import {BaseScript} from "./BaseScript.sol";
import "forge-std/StdJson.sol";

contract DepositScript is BaseScript {
    using AddressCast for address;
    using Endian for bytes32;

    bytes32[] validatorContainer;
    IExoCapsule.ValidatorContainerProof validatorProof;

    uint256 internal constant GENESIS_BLOCK_TIMESTAMP = 1695902400;
    uint256 internal constant SECONDS_PER_SLOT = 12;
    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 constant GWEI_TO_WEI = 1e9;

    function setUp() public virtual override {
        super.setUp();

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        clientGateway =
            IClientChainGateway(payable(stdJson.readAddress(deployedContracts, ".clientChain.clientChainGateway")));
        require(address(clientGateway) != address(0), "clientGateway address should not be empty");

        beaconOracle = EigenLayerBeaconOracle(stdJson.readAddress(deployedContracts, ".clientChain.beaconOracle"));
        require(address(beaconOracle) != address(0), "beacon oracle address should not be empty");

        // load beacon chain validator container and proof from json file
        _loadValidatorContainer();
        _loadValidatorProof();

        if (!useExocorePrecompileMock) {
            _bindPrecompileMocks();
        }

        // transfer some gas fee to depositor, relayer and exocore gateway
        clientChain = vm.createSelectFork(clientChainRPCURL);
        _topUpPlayer(clientChain, address(0), deployer, depositor.addr, 0.2 ether);

        exocore = vm.createSelectFork(exocoreRPCURL);
        _topUpPlayer(exocore, address(0), exocoreGenesis, address(exocoreGateway), 1 ether);
    }

    function run() public {
        bytes memory root = abi.encodePacked(hex"c0fa1dc87438211f4f73fab438558794947572b771f68c905eee959dba104877");
        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(root)
        );
        vm.selectFork(clientChain);

        vm.startBroadcast(depositor.privateKey);
        (bool success,) = address(beaconOracle).call(abi.encodeWithSelector(beaconOracle.addTimestamp.selector, validatorProof.beaconBlockTimestamp));
        vm.stopBroadcast();

        vm.startBroadcast(depositor.privateKey);
        bytes memory msg_ = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            abi.encodePacked(bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS))),
            abi.encodePacked(bytes32(bytes20(depositor.addr))),
            uint256(_getEffectiveBalance(validatorContainer)) * GWEI_TO_WEI
        );
        uint256 nativeFee = clientGateway.quote(msg_);
        try clientGateway.depositBeaconChainValidator{value: nativeFee}(validatorContainer, validatorProof) {
            console.log("finish");
        } catch {
            console.log("fire anyway");
        }
        vm.stopBroadcast();
    }

    function _loadValidatorContainer() internal {
        string memory validatorInfo = vm.readFile("script/validator_container_proof_1711400.json");

        validatorContainer = stdJson.readBytes32Array(validatorInfo, ".ValidatorFields");
        require(validatorContainer.length > 0, "validator container should not be empty");
    }

    function _loadValidatorProof() internal {
        string memory validatorInfo = vm.readFile("script/validator_container_proof_1711400.json");

        uint256 slot = stdJson.readUint(validatorInfo, ".slot");
        validatorProof.beaconBlockTimestamp = GENESIS_BLOCK_TIMESTAMP + SECONDS_PER_SLOT * slot;

        validatorProof.stateRoot = stdJson.readBytes32(validatorInfo, ".beaconStateRoot");
        require(validatorProof.stateRoot != bytes32(0), "state root should not be empty");
        validatorProof.stateRootProof = stdJson.readBytes32Array(validatorInfo, ".StateRootAgainstLatestBlockHeaderProof");
        require(validatorProof.stateRootProof.length == 3, "state root proof should have 3 nodes");
        validatorProof.validatorContainerRootProof = stdJson.readBytes32Array(validatorInfo, ".WithdrawalCredentialProof");
        require(validatorProof.validatorContainerRootProof.length == 46, "validator root proof should have 46 nodes");
        validatorProof.validatorIndex = stdJson.readUint(validatorInfo, ".validatorIndex");
        require(validatorProof.validatorIndex != 0, "validator root index should not be 0");
    }

    function _getEffectiveBalance(bytes32[] storage vc) internal view returns (uint64) {
        return vc[2].fromLittleEndianUint64();
    }
}
