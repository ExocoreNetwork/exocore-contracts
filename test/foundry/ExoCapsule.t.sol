pragma solidity ^0.8.19;

import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";

import "src/interfaces/IExoCapsule.sol";
import "src/core/ExoCapsule.sol";
import {ExoCapsuleStorage} from "src/storage/ExoCapsuleStorage.sol";
import "src/libraries/BeaconChainProofs.sol";
import "src/libraries/Endian.sol";

contract SetUp is Test {
    using stdStorage for StdStorage;
    using Endian for bytes32;

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
    /// @notice The number of slots each epoch in the beacon chain
    uint64 internal constant SLOTS_PER_EPOCH = 32;
    /// @notice The number of seconds in a slot in the beacon chain
    uint64 internal constant SECONDS_PER_SLOT = 12;
    /// @notice Number of seconds per epoch: 384 == 32 slots/epoch * 12 seconds/slot
    uint64 internal constant SECONDS_PER_EPOCH = SLOTS_PER_EPOCH * SECONDS_PER_SLOT;
    uint256 internal constant VERIFY_BALANCE_UPDATE_WINDOW_SECONDS = 4.5 hours;

    uint256 mockProofTimestamp;
    uint256 mockCurrentBlockTimestamp;

    function setUp() public {
        string memory validatorInfo = vm.readFile("test/foundry/test-data/validator_container_proof_8955769.json");

        validatorContainer = stdJson.readBytes32Array(validatorInfo, ".ValidatorFields");
        require(validatorContainer.length > 0, "validator container should not be empty");

        validatorProof.stateRoot = stdJson.readBytes32(validatorInfo, ".beaconStateRoot");
        require(validatorProof.stateRoot != bytes32(0), "state root should not be empty");
        validatorProof.stateRootProof = stdJson.readBytes32Array(
            validatorInfo,
            ".StateRootAgainstLatestBlockHeaderProof"
        );
        require(validatorProof.stateRootProof.length == 3, "state root proof should have 3 nodes");
        validatorProof.validatorContainerRootProof = stdJson.readBytes32Array(
            validatorInfo,
            ".WithdrawalCredentialProof"
        );
        require(validatorProof.validatorContainerRootProof.length == 46, "validator root proof should have 46 nodes");
        validatorProof.validatorIndex = stdJson.readUint(validatorInfo, ".validatorIndex");
        require(validatorProof.validatorIndex != 0, "validator root index should not be 0");

        beaconBlockRoot = stdJson.readBytes32(validatorInfo, ".latestBlockHeaderRoot");
        require(beaconBlockRoot != bytes32(0), "beacon block root should not be empty");

        beaconOracle = IBeaconChainOracle(address(0x123));
        vm.etch(address(beaconOracle), bytes("aabb"));

        capsuleOwner = address(0x125);

        ExoCapsule phantomCapsule = new ExoCapsule();

        address capsuleAddress = _getCapsuleFromWithdrawalCredentials(_getWithdrawalCredentials(validatorContainer));
        vm.etch(capsuleAddress, address(phantomCapsule).code);
        capsule = ExoCapsule(payable(capsuleAddress));
        assertEq(bytes32(capsule.capsuleWithdrawalCredentials()), _getWithdrawalCredentials(validatorContainer));

        stdstore.target(capsuleAddress).sig("gateway()").checked_write(bytes32(uint256(uint160(address(this)))));

        stdstore.target(capsuleAddress).sig("capsuleOwner()").checked_write(bytes32(uint256(uint160(capsuleOwner))));

        stdstore.target(capsuleAddress).sig("beaconOracle()").checked_write(
            bytes32(uint256(uint160(address(beaconOracle))))
        );
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

    function _getEffectiveBalance(bytes32[] storage vc) internal view returns (uint64) {
        return vc[2].fromLittleEndianUint64();
    }

    function _getActivationEpoch(bytes32[] storage vc) internal view returns (uint64) {
        return vc[5].fromLittleEndianUint64();
    }

    function _getExitEpoch(bytes32[] storage vc) internal view returns (uint64) {
        return vc[6].fromLittleEndianUint64();
    }
}

contract VerifyDepositProof is SetUp {
    using BeaconChainProofs for bytes32;
    using stdStorage for StdStorage;

    function test_verifyDepositProof_success() public {
        uint256 activationTimestamp = BEACON_CHAIN_GENESIS_TIME +
            _getActivationEpoch(validatorContainer) *
            SECONDS_PER_EPOCH;
        mockProofTimestamp = activationTimestamp;
        mockCurrentBlockTimestamp = mockProofTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;

        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );

        capsule.verifyDepositProof(validatorContainer, validatorProof);

        ExoCapsuleStorage.Validator memory validator = capsule.getRegisteredValidatorByPubkey(
            _getPubkey(validatorContainer)
        );
        assertEq(uint8(validator.status), uint8(ExoCapsuleStorage.VALIDATOR_STATUS.REGISTERED));
        assertEq(validator.validatorIndex, validatorProof.validatorIndex);
        assertEq(validator.mostRecentBalanceUpdateTimestamp, validatorProof.beaconBlockTimestamp);
        assertEq(validator.restakedBalanceGwei, _getEffectiveBalance(validatorContainer));
    }

    function test_verifyDepositProof_revert_validatorAlreadyDeposited() public {
        uint256 activationTimestamp = BEACON_CHAIN_GENESIS_TIME +
            _getActivationEpoch(validatorContainer) *
            SECONDS_PER_EPOCH;
        mockProofTimestamp = activationTimestamp;
        mockCurrentBlockTimestamp = mockProofTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;

        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );

        capsule.verifyDepositProof(validatorContainer, validatorProof);

        // deposit again should revert
        vm.expectRevert(
            abi.encodeWithSelector(ExoCapsule.DoubleDepositedValidator.selector, _getPubkey(validatorContainer))
        );
        capsule.verifyDepositProof(validatorContainer, validatorProof);
    }

    function test_verifyDepositProof_revert_staleProof() public {
        uint256 activationTimestamp = BEACON_CHAIN_GENESIS_TIME +
            _getActivationEpoch(validatorContainer) *
            SECONDS_PER_EPOCH;
        mockProofTimestamp = activationTimestamp + 1 hours;
        mockCurrentBlockTimestamp = mockProofTimestamp + VERIFY_BALANCE_UPDATE_WINDOW_SECONDS + 1 seconds;
        vm.warp(mockCurrentBlockTimestamp);
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;

        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );

        // deposit should revert because of proof is stale
        vm.expectRevert(
            abi.encodeWithSelector(
                ExoCapsule.StaleValidatorContainer.selector,
                _getPubkey(validatorContainer),
                mockProofTimestamp
            )
        );
        capsule.verifyDepositProof(validatorContainer, validatorProof);
    }

    function test_verifyDepositProof_revert_malformedValidatorContainer() public {
        uint256 activationTimestamp = BEACON_CHAIN_GENESIS_TIME +
            _getActivationEpoch(validatorContainer) *
            SECONDS_PER_EPOCH;
        mockProofTimestamp = activationTimestamp;
        mockCurrentBlockTimestamp = mockProofTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;

        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );

        uint256 snapshot = vm.snapshot();

        // construct malformed validator container that has extra fields
        validatorContainer.push(bytes32(uint256(123)));
        vm.expectRevert(
            abi.encodeWithSelector(ExoCapsule.InvalidValidatorContainer.selector, _getPubkey(validatorContainer))
        );
        capsule.verifyDepositProof(validatorContainer, validatorProof);

        vm.revertTo(snapshot);
        // construct malformed validator container that misses fields
        validatorContainer.pop();
        vm.expectRevert(
            abi.encodeWithSelector(ExoCapsule.InvalidValidatorContainer.selector, _getPubkey(validatorContainer))
        );
        capsule.verifyDepositProof(validatorContainer, validatorProof);
    }

    function test_verifyDepositProof_revert_inactiveValidatorContainer() public {
        uint256 activationTimestamp = BEACON_CHAIN_GENESIS_TIME +
            _getActivationEpoch(validatorContainer) *
            SECONDS_PER_EPOCH;

        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );

        // set proof timestamp before activation epoch
        mockProofTimestamp = activationTimestamp - 1 seconds;
        mockCurrentBlockTimestamp = mockProofTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;
        vm.expectRevert(
            abi.encodeWithSelector(ExoCapsule.InactiveValidatorContainer.selector, _getPubkey(validatorContainer))
        );
        capsule.verifyDepositProof(validatorContainer, validatorProof);
    }

    function test_verifyDepositProof_revert_mismatchWithdrawalCredentials() public {
        uint256 activationTimestamp = BEACON_CHAIN_GENESIS_TIME +
            _getActivationEpoch(validatorContainer) *
            SECONDS_PER_EPOCH;
        mockProofTimestamp = activationTimestamp;
        mockCurrentBlockTimestamp = mockProofTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;

        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );

        // validator container withdrawal credentials are pointed to another capsule
        ExoCapsule anotherCapsule = new ExoCapsule();

        bytes32 gatewaySlot = bytes32(stdstore.target(address(anotherCapsule)).sig("gateway()").find());
        vm.store(address(anotherCapsule), gatewaySlot, bytes32(uint256(uint160(address(this)))));

        bytes32 ownerSlot = bytes32(stdstore.target(address(anotherCapsule)).sig("capsuleOwner()").find());
        vm.store(address(anotherCapsule), ownerSlot, bytes32(uint256(uint160(capsuleOwner))));

        bytes32 beaconOraclerSlot = bytes32(stdstore.target(address(anotherCapsule)).sig("beaconOracle()").find());
        vm.store(address(anotherCapsule), beaconOraclerSlot, bytes32(uint256(uint160(address(beaconOracle)))));

        vm.expectRevert(abi.encodeWithSelector(ExoCapsule.WithdrawalCredentialsNotMatch.selector));
        anotherCapsule.verifyDepositProof(validatorContainer, validatorProof);
    }

    function test_verifyDepositProof_revert_proofNotMatchWithBeaconRoot() public {
        uint256 activationTimestamp = BEACON_CHAIN_GENESIS_TIME +
            _getActivationEpoch(validatorContainer) *
            SECONDS_PER_EPOCH;
        mockProofTimestamp = activationTimestamp;
        mockCurrentBlockTimestamp = mockProofTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;

        bytes32 mismatchBeaconBlockRoot = bytes32(uint256(123));
        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(mismatchBeaconBlockRoot)
        );

        // verify proof against mismatch beacon block root
        vm.expectRevert(
            abi.encodeWithSelector(ExoCapsule.InvalidValidatorContainer.selector, _getPubkey(validatorContainer))
        );
        capsule.verifyDepositProof(validatorContainer, validatorProof);
    }
}
