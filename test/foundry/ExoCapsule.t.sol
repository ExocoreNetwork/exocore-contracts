pragma solidity ^0.8.19;

import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";

import "src/interfaces/IExoCapsule.sol";
import "src/core/ExoCapsule.sol";
import "src/libraries/BeaconChainProofs.sol";

contract SetUp is Test {
    using stdStorage for StdStorage;

    bytes32[] validatorContainer;
    /**
        struct ValidatorContainerProof {
            uint256 beaconBlockTimestamp;
            bytes32 stateRoot;
            bytes32[] stateRootProof;
            bytes32[] validatorContainerRootProof;
            uint256 validatorContainerRootIndex;
        }
    */
    IExoCapsule.ValidatorContainerProof validatorProof;
    bytes32 beaconBlockRoot;

    ExoCapsule capsule;
    IBeaconChainOracle beaconOracle;
    address capsuleOwner;

    uint256 constant BEACON_CHAIN_GENESIS_TIME = 1606824023;
    uint256 constant mockProofSlotsAfterGenesis = 8000;
    uint256 constant mockCurrentBlockSlotsAfterGenesis = 7500;

    function setUp() public {
        string memory validatorInfo = vm.readFile("test/foundry/test-data/validator_container_proof_302913.json");

        validatorContainer = stdJson.readBytes32Array(validatorInfo, ".ValidatorFields");
        require(validatorContainer.length > 0, "validator container should not be empty");
        
        vm.warp(BEACON_CHAIN_GENESIS_TIME + mockCurrentBlockSlotsAfterGenesis * 12);
        validatorProof.beaconBlockTimestamp = BEACON_CHAIN_GENESIS_TIME + mockProofSlotsAfterGenesis * 12;

        validatorProof.stateRoot = stdJson.readBytes32(validatorInfo, ".beaconStateRoot");
        require(validatorProof.stateRoot != bytes32(0), "state root should not be empty");
        validatorProof.stateRootProof = stdJson.readBytes32Array(validatorInfo, ".StateRootAgainstLatestBlockHeaderProof");
        require(validatorProof.stateRootProof.length == 3, "state root proof should have 3 nodes");
        validatorProof.validatorContainerRootProof = stdJson.readBytes32Array(validatorInfo, ".WithdrawalCredentialProof");
        require(validatorProof.validatorContainerRootProof.length == 46, "validator root proof should have 46 nodes");
        validatorProof.validatorIndex = stdJson.readUint(validatorInfo, ".validatorIndex");
        require(validatorProof.validatorIndex != 0, "validator root index should not be 0");

        beaconBlockRoot = stdJson.readBytes32(validatorInfo, ".latestBlockHeaderRoot");
        require(beaconBlockRoot != bytes32(0), "beacon block root should not be empty");

        beaconOracle = IBeaconChainOracle(address(0x123));
        vm.etch(address(beaconOracle), bytes("aabb"));

        capsuleOwner = address(0x125);

        ExoCapsule phantomCapsule = new ExoCapsule(address(this), capsuleOwner, address(beaconOracle));

        address capsuleAddress = _getCapsuleFromWithdrawalCredentials(_getWithdrawalCredentials(validatorContainer));
        vm.etch(capsuleAddress, address(phantomCapsule).code);
        capsule = ExoCapsule(capsuleAddress);

        bytes32 gatewaySlot = bytes32(stdstore.target(capsuleAddress).sig("gateway()").find());
        vm.store(capsuleAddress, gatewaySlot, bytes32(uint256(uint160(address(this)))));

        bytes32 ownerSlot = bytes32(stdstore.target(capsuleAddress).sig("capsuleOwner()").find());
        vm.store(capsuleAddress, ownerSlot, bytes32(uint256(uint160(capsuleOwner))));

        bytes32 beaconOraclerSlot = bytes32(stdstore.target(capsuleAddress).sig("beaconOracle()").find());
        vm.store(capsuleAddress, beaconOraclerSlot, bytes32(uint256(uint160(address(beaconOracle)))));
    }

    function _getCapsuleFromWithdrawalCredentials(bytes32 withdrawalCredentials) internal pure returns (address) {
        return address(bytes20(uint160(uint256(withdrawalCredentials))));
    }

    function _getWithdrawalCredentials(bytes32[] storage vc) internal view returns (bytes32) {
        return vc[1];
    }
}

contract VerifyDepositProof is SetUp {
    using BeaconChainProofs for bytes32;
    function test_verifyDepositProof() public {
        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );

        capsule.verifyDepositProof(validatorContainer, validatorProof);
    }
}