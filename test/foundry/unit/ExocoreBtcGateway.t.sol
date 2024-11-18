// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ExocoreBtcGateway} from "src/core/ExocoreBtcGateway.sol";

import "src/interfaces/precompiles/IAssets.sol";
import "src/interfaces/precompiles/IDelegation.sol";
import "src/interfaces/precompiles/IReward.sol";
import {Errors} from "src/libraries/Errors.sol";
import {SignatureVerifier} from "src/libraries/SignatureVerifier.sol";
import {ExocoreBtcGatewayStorage} from "src/storage/ExocoreBtcGatewayStorage.sol";
import "test/mocks/AssetsMock.sol";
import "test/mocks/DelegationMock.sol";
import "test/mocks/RewardMock.sol";

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract ExocoreBtcGatewayTest is Test {

    using stdStorage for StdStorage;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    ExocoreBtcGateway gateway;
    ExocoreBtcGateway gatewayLogic;
    address owner;
    address user;
    address relayer;
    Player[3] witnesses;
    bytes btcAddress;
    string operator;
    ExocoreBtcGatewayStorage.Transaction txn;

    address public constant EXOCORE_WITNESS = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);

    // chain id from layerzero, virtual for bitcoin since it's not yet a layerzero chain
    string public constant BITCOIN_NAME = "Bitcoin";
    string public constant BITCOIN_METADATA = "Bitcoin";
    string public constant BITCOIN_SIGNATURE_SCHEME = "ECDSA";
    uint8 public constant STAKER_ACCOUNT_LENGTH = 20;

    // virtual token address and token, shared for tokens supported by the gateway
    address public constant VIRTUAL_TOKEN_ADDRESS = 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB;
    bytes public constant VIRTUAL_TOKEN = abi.encodePacked(bytes32(bytes20(VIRTUAL_TOKEN_ADDRESS)));

    uint8 public constant BTC_DECIMALS = 8;
    string public constant BTC_NAME = "BTC";
    string public constant BTC_METADATA = "BTC";
    string public constant BTC_ORACLE_INFO = "BTC,BITCOIN,8";

    uint256 public constant REQUIRED_PROOFS = 2;
    uint256 public constant PROOF_TIMEOUT = 1 days;

    event WitnessAdded(address indexed witness);
    event WitnessRemoved(address indexed witness);
    event AddressRegistered(
        ExocoreBtcGatewayStorage.ClientChainID indexed chainId, bytes depositor, address exocoreAddress
    );
    event DepositCompleted(
        ExocoreBtcGatewayStorage.ClientChainID indexed chainId,
        bytes txTag,
        address indexed exocoreAddress,
        bytes srcAddress,
        uint256 amount,
        uint256 updatedBalance
    );
    event DelegationCompleted(
        ExocoreBtcGatewayStorage.ClientChainID indexed chainId,
        address indexed delegator,
        string operator,
        uint256 amount
    );
    event ProofSubmitted(bytes32 indexed txId, address indexed witness);
    event StakeMsgExecuted(bytes32 indexed txId);
    event BridgeFeeRateUpdated(uint256 newRate);

    event ClientChainRegistered(uint32 clientChainId);
    event ClientChainUpdated(uint32 clientChainId);
    event WhitelistTokenAdded(uint32 clientChainId, address indexed token);
    event WhitelistTokenUpdated(uint32 clientChainId, address indexed token);
    event DelegationFailedForStake(
        ExocoreBtcGatewayStorage.ClientChainID indexed clientChainId,
        address indexed exoDelegator,
        string operator,
        uint256 amount
    );

    function setUp() public {
        owner = address(1);
        user = address(2);
        relayer = address(3);
        witnesses[0] = Player({privateKey: 0xa, addr: vm.addr(0xa)});
        witnesses[1] = Player({privateKey: 0xb, addr: vm.addr(0xb)});
        witnesses[2] = Player({privateKey: 0xc, addr: vm.addr(0xc)});

        btcAddress = bytes("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        operator = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";

        // Deploy mock contracts and bind to precompile addresses
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory RewardMockCode = vm.getDeployedCode("RewardMock.sol");
        vm.etch(REWARD_PRECOMPILE_ADDRESS, RewardMockCode);

        // Deploy and initialize gateway
        gatewayLogic = new ExocoreBtcGateway();
        gateway = ExocoreBtcGateway(address(new TransparentUpgradeableProxy(address(gatewayLogic), address(0), "")));
        address[] memory initialWitnesses = new address[](1);
        initialWitnesses[0] = witnesses[0].addr;
        gateway.initialize(owner, initialWitnesses);
    }

    function test_initialize() public {
        assertEq(gateway.owner(), owner);
        assertTrue(gateway.authorizedWitnesses(witnesses[0].addr));
        assertEq(gateway.authorizedWitnessCount(), 2);
    }

    function test_AddWitness() public {
        vm.prank(owner);

        vm.expectEmit(true, false, false, false);
        emit WitnessAdded(witnesses[1].addr);

        gateway.addWitness(witnesses[1].addr);
        assertTrue(gateway.authorizedWitnesses(witnesses[1].addr));
        assertEq(gateway.authorizedWitnessCount(), 3);
    }

    function test_AddWitness_RevertNotOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        gateway.addWitness(witnesses[1].addr);
    }

    function test_AddWitness_RevertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(Errors.ZeroAddress.selector);
        gateway.addWitness(address(0));
    }

    function test_AddWitness_RevertAlreadyAuthorized() public {
        // First add a witness
        vm.startPrank(owner);
        gateway.addWitness(witnesses[1].addr);

        // Try to add the same witness again
        vm.expectRevert("Witness already authorized");
        gateway.addWitness(witnesses[1].addr);
        vm.stopPrank();
    }

    function test_AddWitness_RevertWhenPaused() public {
        vm.startPrank(owner);
        gateway.pause();

        vm.expectRevert("Pausable: paused");
        gateway.addWitness(witnesses[1].addr);
        vm.stopPrank();
    }

    function test_RemoveWitness() public {
        vm.prank(owner);

        vm.expectEmit(true, false, false, false);
        emit WitnessRemoved(witnesses[0].addr);

        gateway.removeWitness(witnesses[0].addr);
        assertFalse(gateway.authorizedWitnesses(witnesses[0].addr));
        assertEq(gateway.authorizedWitnessCount(), 1);
    }

    function test_RemoveWitness_RevertNotOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        gateway.removeWitness(witnesses[0].addr);
    }

    function test_RemoveWitness_RevertWitnessNotAuthorized() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Errors.WitnessNotAuthorized.selector, witnesses[1].addr));
        gateway.removeWitness(witnesses[1].addr);
    }

    function test_RemoveWitness_RevertWhenPaused() public {
        vm.startPrank(owner);
        gateway.pause();

        vm.expectRevert("Pausable: paused");
        gateway.removeWitness(witnesses[0].addr);
        vm.stopPrank();
    }

    function test_RemoveWitness_CannotRemoveLastWitness() public {
        // First remove all witnesses except one
        vm.startPrank(owner);
        for (uint256 i = 0; i < witnesses.length; i++) {
            if (gateway.authorizedWitnesses(witnesses[i].addr)) {
                gateway.removeWitness(witnesses[i].addr);
            }
        }

        // Try to remove the hardcoded witness
        vm.expectRevert(Errors.CannotRemoveLastWitness.selector);
        gateway.removeWitness(EXOCORE_WITNESS);
        vm.stopPrank();
    }

    function test_RemoveWitness_MultipleRemovals() public {
        vm.startPrank(owner);

        // First add another witness
        gateway.addWitness(witnesses[1].addr);
        assertTrue(gateway.authorizedWitnesses(witnesses[1].addr));
        assertEq(gateway.authorizedWitnessCount(), 3);

        // Remove first witness
        gateway.removeWitness(witnesses[0].addr);
        assertFalse(gateway.authorizedWitnesses(witnesses[0].addr));
        assertTrue(gateway.authorizedWitnesses(witnesses[1].addr));
        assertEq(gateway.authorizedWitnessCount(), 2);

        // Remove second witness
        gateway.removeWitness(witnesses[1].addr);
        assertFalse(gateway.authorizedWitnesses(witnesses[1].addr));
        assertEq(gateway.authorizedWitnessCount(), 1);

        vm.stopPrank();
    }

    function test_UpdateBridgeFee() public {
        uint256 newFee = 500; // 5%

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit BridgeFeeRateUpdated(newFee);

        gateway.updateBridgeFeeRate(newFee);
        assertEq(gateway.bridgeFeeRate(), newFee);
    }

    function test_UpdateBridgeFee_Zero() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit BridgeFeeRateUpdated(0);

        gateway.updateBridgeFeeRate(0);
        assertEq(gateway.bridgeFeeRate(), 0);
    }

    function test_UpdateBridgeFee_MaxFee() public {
        uint256 maxFee = 1000; // 10%

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit BridgeFeeRateUpdated(maxFee);

        gateway.updateBridgeFeeRate(maxFee);
        assertEq(gateway.bridgeFeeRate(), maxFee);
    }

    function test_UpdateBridgeFee_RevertExceedMax() public {
        vm.prank(owner);
        vm.expectRevert("Fee cannot exceed 10%");
        gateway.updateBridgeFeeRate(1001); // 10.01%
    }

    function test_UpdateBridgeFee_RevertNotOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        gateway.updateBridgeFeeRate(500);
    }

    function test_UpdateBridgeFee_RevertWhenPaused() public {
        vm.startPrank(owner);
        gateway.pause();

        vm.expectRevert("Pausable: paused");
        gateway.updateBridgeFeeRate(500);
        vm.stopPrank();
    }

    function test_UpdateBridgeFee_MultipleFeeUpdates() public {
        vm.startPrank(owner);

        // First update
        uint256 firstFee = 300;
        vm.expectEmit(true, false, false, true);
        emit BridgeFeeRateUpdated(firstFee);
        gateway.updateBridgeFeeRate(firstFee);
        assertEq(gateway.bridgeFeeRate(), firstFee);

        // Second update
        uint256 secondFee = 700;
        vm.expectEmit(true, false, false, true);
        emit BridgeFeeRateUpdated(secondFee);
        gateway.updateBridgeFeeRate(secondFee);
        assertEq(gateway.bridgeFeeRate(), secondFee);

        vm.stopPrank();
    }

    function test_ActivateStakingForClientChain() public {
        vm.startPrank(owner);

        // Mock successful chain registration
        bytes memory chainRegisterCall = abi.encodeWithSelector(
            IAssets.registerOrUpdateClientChain.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            STAKER_ACCOUNT_LENGTH,
            BITCOIN_NAME,
            BITCOIN_METADATA,
            BITCOIN_SIGNATURE_SCHEME
        );
        vm.mockCall(
            ASSETS_PRECOMPILE_ADDRESS,
            chainRegisterCall,
            abi.encode(true, false) // success = true, updated = false (new registration)
        );

        // Mock successful token registration
        bytes memory tokenRegisterCall = abi.encodeWithSelector(
            IAssets.registerToken.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            VIRTUAL_TOKEN,
            BTC_DECIMALS,
            BTC_NAME,
            BTC_METADATA,
            BTC_ORACLE_INFO
        );
        vm.mockCall(
            ASSETS_PRECOMPILE_ADDRESS,
            tokenRegisterCall,
            abi.encode(true) // success = true
        );

        vm.expectEmit(true, false, false, false);
        emit ClientChainRegistered(uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)));
        vm.expectEmit(true, false, false, false);
        emit WhitelistTokenAdded(uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)), VIRTUAL_TOKEN_ADDRESS);

        gateway.activateStakingForClientChain(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin);
        vm.stopPrank();
    }

    function test_ActivateStakingForClientChain_UpdateExisting() public {
        vm.startPrank(owner);

        // Mock chain update
        bytes memory chainRegisterCall = abi.encodeWithSelector(
            IAssets.registerOrUpdateClientChain.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            STAKER_ACCOUNT_LENGTH,
            BITCOIN_NAME,
            BITCOIN_METADATA,
            BITCOIN_SIGNATURE_SCHEME
        );
        vm.mockCall(
            ASSETS_PRECOMPILE_ADDRESS,
            chainRegisterCall,
            abi.encode(true, true) // success = true, updated = true (updating existing)
        );

        // Mock token update
        bytes memory tokenRegisterCall = abi.encodeWithSelector(
            IAssets.registerToken.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            VIRTUAL_TOKEN,
            BTC_DECIMALS,
            BTC_NAME,
            BTC_METADATA,
            BTC_ORACLE_INFO
        );
        vm.mockCall(
            ASSETS_PRECOMPILE_ADDRESS,
            tokenRegisterCall,
            abi.encode(false) // registration fails, indicating existing token
        );

        // Mock token update call
        bytes memory tokenUpdateCall = abi.encodeWithSelector(
            IAssets.updateToken.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            VIRTUAL_TOKEN,
            BTC_METADATA
        );
        vm.mockCall(
            ASSETS_PRECOMPILE_ADDRESS,
            tokenUpdateCall,
            abi.encode(true) // update succeeds
        );

        vm.expectEmit(true, false, false, false);
        emit ClientChainUpdated(uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)));
        vm.expectEmit(true, false, false, false);
        emit WhitelistTokenUpdated(uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)), VIRTUAL_TOKEN_ADDRESS);

        gateway.activateStakingForClientChain(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin);
        vm.stopPrank();
    }

    function test_ActivateStakingForClientChain_RevertChainRegistrationFailed() public {
        vm.startPrank(owner);

        // Mock failed chain registration
        bytes memory chainRegisterCall = abi.encodeWithSelector(
            IAssets.registerOrUpdateClientChain.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            STAKER_ACCOUNT_LENGTH,
            BITCOIN_NAME,
            BITCOIN_METADATA,
            BITCOIN_SIGNATURE_SCHEME
        );
        vm.mockCall(
            ASSETS_PRECOMPILE_ADDRESS,
            chainRegisterCall,
            abi.encode(false, false) // registration failed
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.RegisterClientChainToExocoreFailed.selector,
                uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin))
            )
        );
        gateway.activateStakingForClientChain(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin);
        vm.stopPrank();
    }

    function test_ActivateStakingForClientChain_RevertTokenRegistrationAndUpdateFailed() public {
        vm.startPrank(owner);

        // Mock successful chain registration
        bytes memory chainRegisterCall = abi.encodeWithSelector(
            IAssets.registerOrUpdateClientChain.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            STAKER_ACCOUNT_LENGTH,
            BITCOIN_NAME,
            BITCOIN_METADATA,
            BITCOIN_SIGNATURE_SCHEME
        );
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, chainRegisterCall, abi.encode(true, false));

        // Mock failed token registration
        bytes memory tokenRegisterCall = abi.encodeWithSelector(
            IAssets.registerToken.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            VIRTUAL_TOKEN,
            BTC_DECIMALS,
            BTC_NAME,
            BTC_METADATA,
            BTC_ORACLE_INFO
        );
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, tokenRegisterCall, abi.encode(false));

        // Mock failed token update
        bytes memory tokenUpdateCall = abi.encodeWithSelector(
            IAssets.updateToken.selector,
            uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
            VIRTUAL_TOKEN,
            BTC_METADATA
        );
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, tokenUpdateCall, abi.encode(false));

        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.AddWhitelistTokenFailed.selector,
                uint32(uint8(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin)),
                bytes32(VIRTUAL_TOKEN)
            )
        );
        gateway.activateStakingForClientChain(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin);
        vm.stopPrank();
    }

    function test_ActivateStakingForClientChain_RevertInvalidChain() public {
        vm.prank(owner);
        vm.expectRevert(Errors.InvalidClientChain.selector);
        gateway.activateStakingForClientChain(ExocoreBtcGatewayStorage.ClientChainID.None);
    }

    function test_ActivateStakingForClientChain_RevertNotOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        gateway.activateStakingForClientChain(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin);
    }

    function test_ActivateStakingForClientChain_RevertWhenPaused() public {
        vm.startPrank(owner);
        gateway.pause();

        vm.expectRevert("Pausable: paused");
        gateway.activateStakingForClientChain(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin);
        vm.stopPrank();
    }

    function test_SubmitProofForStakeMsg() public {
        _addAllWitnesses();

        // Create stake message
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1-0")
        });

        bytes32 txId = _getMessageHash(stakeMsg);
        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        // Submit proof from first witness
        vm.prank(relayer);
        vm.expectEmit(true, true, false, true);
        emit ProofSubmitted(txId, witnesses[0].addr);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, signature);

        // mock Assets precompile deposit success and Delegation precompile delegate success
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IAssets.depositLST.selector), abi.encode(true));
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IDelegation.delegate.selector), abi.encode(true)
        );

        // Submit proof from second witness
        signature = _generateSignature(stakeMsg, witnesses[1].privateKey);
        vm.prank(witnesses[1].addr);
        vm.expectEmit(true, true, false, true);
        emit ProofSubmitted(txId, witnesses[1].addr);

        // This should trigger message execution as we have enough proofs
        vm.expectEmit(true, false, false, false);
        emit StakeMsgExecuted(txId);
        gateway.submitProofForStakeMsg(witnesses[1].addr, stakeMsg, signature);

        // Verify message was processed
        assertTrue(gateway.processedClientChainTxs(stakeMsg.chainId, stakeMsg.txTag));
        assertTrue(gateway.processedTransactions(txId));
    }

    function test_SubmitProofForStakeMsg_RevertInvalidSignature() public {
        _addAllWitnesses();

        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1-0")
        });

        bytes memory invalidSignature = bytes("invalid");

        vm.prank(relayer);
        vm.expectRevert(SignatureVerifier.InvalidSignature.selector);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, invalidSignature);
    }

    function test_SubmitProofForStakeMsg_RevertUnauthorizedWitness() public {
        _addAllWitnesses();

        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        Player memory unauthorizedWitness = Player({privateKey: 99, addr: vm.addr(99)});
        bytes memory signature = _generateSignature(stakeMsg, unauthorizedWitness.privateKey);

        vm.prank(unauthorizedWitness.addr);
        vm.expectRevert(abi.encodeWithSelector(Errors.WitnessNotAuthorized.selector, unauthorizedWitness.addr));
        gateway.submitProofForStakeMsg(unauthorizedWitness.addr, stakeMsg, signature);
    }

    function test_SubmitProofForStakeMsg_ExpiredBeforeConsensus() public {
        _addAllWitnesses();

        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // Submit proofs from REQUIRED_PROOFS - 1 witnesses
        for (uint256 i = 0; i < REQUIRED_PROOFS - 1; i++) {
            bytes memory signature = _generateSignature(stakeMsg, witnesses[i].privateKey);
            vm.prank(relayer);
            gateway.submitProofForStakeMsg(witnesses[i].addr, stakeMsg, signature);
        }

        // Move time forward past expiry
        vm.warp(block.timestamp + PROOF_TIMEOUT + 1);

        // Submit the last proof
        bytes memory lastSignature = _generateSignature(stakeMsg, witnesses[REQUIRED_PROOFS - 1].privateKey);
        vm.prank(relayer);
        gateway.submitProofForStakeMsg(witnesses[REQUIRED_PROOFS - 1].addr, stakeMsg, lastSignature);

        // Verify transaction is restarted owing to expired and not processed
        bytes32 messageHash = _getMessageHash(stakeMsg);
        assertEq(uint8(gateway.getTransactionStatus(messageHash)), uint8(ExocoreBtcGatewayStorage.TxStatus.Pending));
        assertEq(gateway.getTransactionProofCount(messageHash), 1);
        assertFalse(gateway.processedClientChainTxs(stakeMsg.chainId, stakeMsg.txTag));
    }

    function test_SubmitProofForStakeMsg_RestartExpiredTransaction() public {
        _addAllWitnesses();

        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // First witness submits proof
        bytes memory signature0 = _generateSignature(stakeMsg, witnesses[0].privateKey);
        vm.prank(relayer);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, signature0);

        // Move time forward past expiry
        vm.warp(block.timestamp + PROOF_TIMEOUT + 1);

        // Same witness submits proof again to restart transaction
        bytes memory signature0Restart = _generateSignature(stakeMsg, witnesses[0].privateKey);
        vm.prank(relayer);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, signature0Restart);

        bytes32 messageHash = _getMessageHash(stakeMsg);

        // Verify transaction is restarted
        assertEq(uint8(gateway.getTransactionStatus(messageHash)), uint8(ExocoreBtcGatewayStorage.TxStatus.Pending));
        assertEq(gateway.getTransactionProofCount(messageHash), 1);
        assertTrue(gateway.getTransactionWitnessTime(messageHash, witnesses[0].addr) > 0);
        assertFalse(gateway.processedTransactions(messageHash));
    }

    function test_SubmitProofForStakeMsg_JoinRestartedTransaction() public {
        _addAllWitnesses();

        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // First witness submits proof
        bytes memory signature0 = _generateSignature(stakeMsg, witnesses[0].privateKey);
        vm.prank(relayer);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, signature0);

        // Move time forward past expiry
        vm.warp(block.timestamp + PROOF_TIMEOUT + 1);

        // Second witness restarts transaction
        bytes memory signature1 = _generateSignature(stakeMsg, witnesses[1].privateKey);
        vm.prank(relayer);
        gateway.submitProofForStakeMsg(witnesses[1].addr, stakeMsg, signature1);

        // as PROOFS_REQUIRED is 2, the transaction should be processed after another witness submits proof

        // mock Assets precompile deposit success and Delegation precompile delegate success
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IAssets.depositLST.selector), abi.encode(true));
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IDelegation.delegate.selector), abi.encode(true)
        );

        // First witness can submit proof again in new round
        bytes memory signature0New = _generateSignature(stakeMsg, witnesses[0].privateKey);
        vm.prank(relayer);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, signature0New);

        bytes32 messageHash = _getMessageHash(stakeMsg);

        // Verify both witnesses' proofs are counted
        assertEq(
            uint8(gateway.getTransactionStatus(messageHash)),
            uint8(ExocoreBtcGatewayStorage.TxStatus.NotStartedOrProcessed)
        );
        assertTrue(gateway.processedTransactions(messageHash));
        assertTrue(gateway.processedClientChainTxs(stakeMsg.chainId, stakeMsg.txTag));
        assertTrue(gateway.getTransactionWitnessTime(messageHash, witnesses[0].addr) > 0); // mapping can not be deleted
            // even if we delete txn after processing
        assertTrue(gateway.getTransactionWitnessTime(messageHash, witnesses[1].addr) > 0); // mapping can not be deleted
            // even if we delete txn after processing
    }

    function test_SubmitProofForStakeMsg_RevertDuplicateProofInSameRound() public {
        _addAllWitnesses();

        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // First submission
        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);
        vm.prank(relayer);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, signature);

        // Try to submit again in same round
        bytes memory signatureSecond = _generateSignature(stakeMsg, witnesses[0].privateKey);
        vm.prank(relayer);
        vm.expectRevert(Errors.WitnessAlreadySubmittedProof.selector);
        gateway.submitProofForStakeMsg(witnesses[0].addr, stakeMsg, signatureSecond);
    }

    function test_ProcessStakeMessage_RegisterNewAddress() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: "",
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // mock Assets precompile deposit success and Delegation precompile delegate success
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IAssets.depositLST.selector), abi.encode(true));
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IDelegation.delegate.selector), abi.encode(true)
        );

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit AddressRegistered(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, btcAddress, user);
        gateway.processStakeMessage(witnesses[0].addr, stakeMsg, signature);

        // Verify address registration
        assertEq(gateway.getClientChainAddress(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, user), btcAddress);
    }

    function test_ProcessStakeMessage_WithBridgeFee() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // first owner updates bridge fee
        vm.prank(owner);
        gateway.updateBridgeFeeRate(100);

        // then relayer submits proof and we should see the bridge fee deducted from the amount
        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        // mock Assets precompile deposit success and Delegation precompile delegate success
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IAssets.depositLST.selector), abi.encode(true));
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IDelegation.delegate.selector), abi.encode(true)
        );
        uint256 amountAfterFee = 1 ether - 1 ether * 100 / 10_000;

        vm.expectEmit(true, true, true, true, address(gateway));
        emit DepositCompleted(
            ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            stakeMsg.txTag,
            user,
            stakeMsg.srcAddress,
            amountAfterFee,
            stakeMsg.amount
        );

        vm.expectEmit(true, true, true, true, address(gateway));
        emit DelegationCompleted(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, user, operator, amountAfterFee);

        vm.prank(relayer);
        gateway.processStakeMessage(witnesses[0].addr, stakeMsg, signature);
    }

    function test_ProcessStakeMessage_WithDelegation() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // mock Assets precompile deposit success and Delegation precompile delegate success
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, abi.encodeWithSignature(IAssets.deposit.selector), abi.encode(true));
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSignature(IDelegation.delegate.selector), abi.encode(true)
        );

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit DelegationCompleted(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, user, operator, 1 ether);
        gateway.processStakeMessage(witnesses[0], stakeMsg, signature);
    }

    function test_ProcessStakeMessage_DelegationFailureNotRevert() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: operator,
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // mock Assets precompile deposit success and Delegation precompile delegate failure
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, abi.encodeWithSignature(IAssets.deposit.selector), abi.encode(true));
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSignature(IDelegation.delegate.selector), abi.encode(false)
        );

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(relayer);
        // deposit should be successful
        vm.expectEmit(true, true, true, true);
        emit DepositCompleted(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, user, 1 ether);

        // delegation should fail
        vm.expectEmit(true, true, true, true);
        emit DelegationFailedForStake(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, user, operator, 1 ether);

        gateway.processStakeMessage(witnesses[0], stakeMsg, signature);
    }

    function test_ProcessStakeMessage_RevertOnDepositFailure() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: "",
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        // mock Assets precompile deposit failure
        vm.mockCall(ASSETS_PRECOMPILE_ADDRESS, abi.encodeWithSignature(IAssets.deposit.selector), abi.encode(false));

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(Errors.DepositFailed.selector, bytes("tx1")));
        gateway.processStakeMessage(witnesses[0], stakeMsg, signature);
    }

    function test_ProcessStakeMessage_RevertWhenPaused() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: "",
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(owner);
        gateway.pause();

        vm.prank(witnesses[0]);
        vm.expectRevert("Pausable: paused");
        gateway.processStakeMessage(witnesses[0], stakeMsg, signature);
    }

    function test_ProcessStakeMessage_RevertUnauthorizedWitness() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: "",
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        Player memory unauthorizedWitness = Player({addr: vm.addr(0x999), privateKey: 0x999});
        bytes memory signature = _generateSignature(stakeMsg, unauthorizedWitness.privateKey);

        vm.prank(unauthorizedWitness);
        vm.expectRevert(abi.encodeWithSelector(Errors.WitnessNotAuthorized.selector, unauthorizedWitness));
        gateway.processStakeMessage(unauthorizedWitness, stakeMsg, signature);
    }

    function test_ProcessStakeMessage_RevertInvalidStakeMessage() public {
        // Create invalid message with all zero values
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.None,
            srcAddress: bytes(""),
            exocoreAddress: address(0),
            operator: "",
            amount: 0,
            nonce: 0,
            txTag: bytes("")
        });

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(relayer);
        vm.expectRevert(Errors.InvalidStakeMessage.selector);
        gateway.processStakeMessage(witnesses[0], stakeMsg, signature);
    }

    function test_ProcessStakeMessage_RevertZeroExocoreAddressBeforeRegistration() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: address(0), // Zero address
            operator: "",
            amount: 1 ether,
            nonce: 1,
            txTag: bytes("tx1")
        });

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(relayer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        gateway.processStakeMessage(witnesses[0], stakeMsg, signature);
    }

    function test_ProcessStakeMessage_RevertInvalidNonce() public {
        ExocoreBtcGatewayStorage.StakeMsg memory stakeMsg = ExocoreBtcGatewayStorage.StakeMsg({
            chainId: ExocoreBtcGatewayStorage.ClientChainID.Bitcoin,
            srcAddress: btcAddress,
            exocoreAddress: user,
            operator: "",
            amount: 1 ether,
            nonce: gateway.nextInboundNonce() + 1,
            txTag: bytes("tx1")
        });

        bytes memory signature = _generateSignature(stakeMsg, witnesses[0].privateKey);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.UnexpectedInboundNonce.selector, gateway.nextInboundNonce(), stakeMsg.nonce)
        );
        gateway.processStakeMessage(witnesses[0], stakeMsg, signature);
    }

    function test_DelegateTo() public {
        // Setup: Register user's client chain address first
        _mockRegisterAddress(user, btcAddress);

        // mock delegation precompile delegate success
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSignature(IDelegation.delegate.selector), abi.encode(true)
        );

        vm.prank(user);
        vm.expectEmit(true, true, true, true);
        emit DelegationCompleted(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, user, operator, 1 ether);

        gateway.delegateTo(ExocoreBtcGatewayStorage.Token.BTC, operator, 1 ether);

        // Verify nonce increment
        assertEq(gateway.delegationNonce(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin), 1);
    }

    function test_DelegateTo_RevertZeroAmount() public {
        _mockRegisterAddress(user, btcAddress);

        vm.prank(user);
        vm.expectRevert(Errors.ZeroAmount.selector);
        gateway.delegateTo(ExocoreBtcGatewayStorage.Token.BTC, operator, 0);
    }

    function test_DelegateTo_RevertWhenPaused() public {
        _mockRegisterAddress(user, btcAddress);

        vm.prank(owner);
        gateway.pause();

        vm.prank(user);
        vm.expectRevert("Pausable: paused");
        gateway.delegateTo(ExocoreBtcGatewayStorage.Token.BTC, operator, 1 ether);
    }

    function test_DelegateTo_RevertNotRegistered() public {
        // Don't register user's address

        vm.prank(user);
        vm.expectRevert(Errors.AddressNotRegistered.selector);
        gateway.delegateTo(ExocoreBtcGatewayStorage.Token.BTC, operator, 1 ether);
    }

    function test_DelegateTo_RevertInvalidOperator() public {
        _mockRegisterAddress(user, btcAddress);

        string memory invalidOperator = "not-a-bech32-address";

        vm.prank(user);
        vm.expectRevert(Errors.InvalidOperator.selector);
        gateway.delegateTo(ExocoreBtcGatewayStorage.Token.BTC, invalidOperator, 1 ether);
    }

    function test_DelegateTo_RevertDelegationFailed() public {
        _mockRegisterAddress(user, btcAddress);

        // Mock delegation failure
        vm.mockCall(
            DELEGATION_PRECOMPILE_ADDRESS, abi.encodeWithSignature(IDelegation.delegate.selector), abi.encode(false)
        );

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Errors.DelegationFailed.selector));
        gateway.delegateTo(ExocoreBtcGatewayStorage.Token.BTC, operator, 1 ether);
    }

    // Helper functions
    function _mockRegisterAddress(address exocoreAddr, bytes memory btcAddr) internal {
        stdstore.target(address(gateway)).sig("inboundRegistry(ClientChainID, bytes)").with_key(
            ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, btcAddr
        ).checked_write(exocoreAddr);
        stdstore.target(address(gateway)).sig("outboundRegistry(ClientChainID, address)").with_key(
            ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, exocoreAddr
        ).checked_write(btcAddr);
        assertEq(gateway.inboundRegistry(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, btcAddr), exocoreAddr);
        assertEq(gateway.outboundRegistry(ExocoreBtcGatewayStorage.ClientChainID.Bitcoin, exocoreAddr), btcAddr);
    }

    function _addAllWitnesses() internal {
        for (uint256 i = 0; i < witnesses.length; i++) {
            if (!gateway.authorizedWitnesses(witnesses[i].addr)) {
                vm.prank(owner);
                gateway.addWitness(witnesses[i].addr);
            }
        }
    }

    function _getMessageHash(ExocoreBtcGatewayStorage.StakeMsg memory msg_) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                msg_.chainId, // ClientChainID
                msg_.srcAddress, // bytes - Bitcoin address
                msg_.exocoreAddress, // address
                msg_.operator, // string
                msg_.amount, // uint256
                msg_.nonce, // uint64
                msg_.txTag // bytes
            )
        );
    }

    function _generateSignature(ExocoreBtcGatewayStorage.StakeMsg memory msg_, uint256 privateKey)
        internal
        pure
        returns (bytes memory)
    {
        // Encode all fields of StakeMsg in order
        bytes32 messageHash = _getMessageHash(msg_);

        // Sign the encoded message hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);

        // Return the signature in the format expected by the contract
        return abi.encodePacked(r, s, v);
    }

}
