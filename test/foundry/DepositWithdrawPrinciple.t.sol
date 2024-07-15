pragma solidity ^0.8.19;

import "../../src/core/ExoCapsule.sol";
import "../../src/core/ExocoreGateway.sol";

import {IExoCapsule} from "../../src/interfaces/IExoCapsule.sol";
import {ILSTRestakingController} from "../../src/interfaces/ILSTRestakingController.sol";

import "../../src/storage/GatewayStorage.sol";
import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "forge-std/console.sol";

contract DepositWithdrawPrincipalTest is ExocoreDeployer {

    using AddressCast for address;
    using stdStorage for StdStorage;

    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawPrincipalResult(
        bool indexed success, address indexed token, address indexed withdrawer, uint256 amount
    );
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event MessageProcessed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event CapsuleCreated(address owner, address capsule);
    event StakedWithCapsule(address staker, address capsule);

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200_000;
    uint64 public constant MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR = 32e9;

    function test_LSTDepositWithdrawByLayerZero() public {
        Player memory depositor = players[0];
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(depositor.addr, 1_000_000);
        vm.stopPrank();

        // transfer some gas fee to depositor
        deal(depositor.addr, 1e22);
        // transfer some gas fee to exocore gateway as it has to pay for the relay fee to layerzero endpoint when
        // sending back response
        deal(address(exocoreGateway), 1e22);

        uint256 depositAmount = 10_000;
        uint256 withdrawAmount = 100;
        uint256 lastlyUpdatedPrincipalBalance;

        // before deposit we should add whitelist tokens
        test_AddWhitelistTokens();

        _testLSTDeposit(depositor, depositAmount, lastlyUpdatedPrincipalBalance);

        lastlyUpdatedPrincipalBalance += depositAmount;

        _testLSTWithdraw(depositor, withdrawAmount, lastlyUpdatedPrincipalBalance);
    }

    function _testLSTDeposit(Player memory depositor, uint256 depositAmount, uint256 lastlyUpdatedPrincipalBalance)
        internal
    {
        // -- deposit workflow test --

        vm.startPrank(depositor.addr);
        restakeToken.approve(address(vault), type(uint256).max);

        // first user call client chain gateway to deposit

        // estimate l0 relay fee that the user should pay
        uint64 depositRequestNonce = 1;
        bytes memory depositRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(depositor.addr)),
            depositAmount
        );
        uint256 depositRequestNativeFee = clientGateway.quote(depositRequestPayload);
        bytes32 depositRequestId = generateUID(depositRequestNonce, true);
        // depositor should transfer deposited token to vault
        vm.expectEmit(true, true, false, true, address(restakeToken));
        emit Transfer(depositor.addr, address(vault), depositAmount);
        // client chain layerzero endpoint should emit the message packet including deposit payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            depositRequestNonce,
            depositRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_DEPOSIT, depositRequestId, depositRequestNonce, depositRequestNativeFee
        );
        clientGateway.deposit{value: depositRequestNativeFee}(address(restakeToken), depositAmount);

        // second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        lastlyUpdatedPrincipalBalance += depositAmount;
        uint64 depositResponseNonce = 2;
        bytes memory depositResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, depositRequestNonce, true, lastlyUpdatedPrincipalBalance);
        uint256 depositResponseNativeFee = exocoreGateway.quote(clientChainId, depositResponsePayload);
        bytes32 depositResponseId = generateUID(depositResponseNonce, false);
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            depositResponseNonce,
            depositResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(
            GatewayStorage.Action.RESPOND, depositResponseId, depositResponseNonce, depositResponseNativeFee
        );
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), depositRequestNonce),
            address(exocoreGateway),
            depositRequestId,
            depositRequestPayload,
            bytes("")
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain
        // endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositResult(true, address(restakeToken), depositor.addr, depositAmount);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), depositResponseNonce),
            address(clientGateway),
            depositResponseId,
            depositResponsePayload,
            bytes("")
        );
    }

    function _testLSTWithdraw(Player memory withdrawer, uint256 withdrawAmount, uint256 lastlyUpdatedPrincipalBalance)
        internal
    {
        // -- withdraw principal workflow --

        // first user call client chain gateway to withdraw

        // estimate l0 relay fee that the user should pay
        uint64 withdrawRequestNonce = 2;
        bytes memory withdrawRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(withdrawer.addr)),
            withdrawAmount
        );
        uint256 withdrawRequestNativeFee = clientGateway.quote(withdrawRequestPayload);
        bytes32 withdrawRequestId = generateUID(withdrawRequestNonce, true);
        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            withdrawRequestNonce,
            withdrawRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE,
            withdrawRequestId,
            withdrawRequestNonce,
            withdrawRequestNativeFee
        );
        clientGateway.withdrawPrincipalFromExocore{value: withdrawRequestNativeFee}(
            address(restakeToken), withdrawAmount
        );

        // second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        uint64 withdrawResponseNonce = 3;
        lastlyUpdatedPrincipalBalance -= withdrawAmount;
        bytes memory withdrawResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, withdrawRequestNonce, true, lastlyUpdatedPrincipalBalance);
        uint256 withdrawResponseNativeFee = exocoreGateway.quote(clientChainId, withdrawResponsePayload);
        bytes32 withdrawResponseId = generateUID(withdrawResponseNonce, false);

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            withdrawResponseNonce,
            withdrawResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(
            GatewayStorage.Action.RESPOND, withdrawResponseId, withdrawResponseNonce, withdrawResponseNativeFee
        );
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), withdrawRequestNonce),
            address(exocoreGateway),
            withdrawRequestId,
            withdrawRequestPayload,
            bytes("")
        );

        // third layerzero relayers should watch the response message packet and relay the message to source chain
        // endpoint

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit WithdrawPrincipalResult(true, address(restakeToken), withdrawer.addr, withdrawAmount);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), withdrawResponseNonce),
            address(clientGateway),
            withdrawResponseId,
            withdrawResponsePayload,
            bytes("")
        );
    }

    function test_NativeDepositWithdraw() public {
        Player memory depositor = players[0];
        Player memory relayer = players[1];

        uint256 lastlyUpdatedPrincipalBalance;

        // transfer some ETH to depositor for staking and paying for gas fee
        deal(depositor.addr, 1e22);
        // transfer some gas fee to relayer for paying for onboarding cross-chain message packet
        deal(relayer.addr, 1e22);
        // transfer some gas fee to exocore gateway as it has to pay for the relay fee to layerzero endpoint when
        // sending back response
        deal(address(exocoreGateway), 1e22);

        // before deposit we should add whitelist tokens
        test_AddWhitelistTokens();

        _testNativeDeposit(depositor, relayer, lastlyUpdatedPrincipalBalance);
        lastlyUpdatedPrincipalBalance += 32 ether;
        _testNativeWithdraw(depositor, relayer, lastlyUpdatedPrincipalBalance);
    }

    function _testNativeDeposit(Player memory depositor, Player memory relayer, uint256 lastlyUpdatedPrincipalBalance)
        internal
    {
        // before native stake and deposit, we simulate proper block environment states to make proof valid
        _simulateBlockEnvironmentForNativeDeposit();

        // 1. firstly depositor should stake to beacon chain by depositing 32 ETH to ETHPOS contract
        IExoCapsule expectedCapsule = IExoCapsule(
            Create2.computeAddress(
                bytes32(uint256(uint160(depositor.addr))),
                keccak256(abi.encodePacked(BEACON_PROXY_BYTECODE, abi.encode(address(capsuleBeacon), ""))),
                address(clientGateway)
            )
        );
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit CapsuleCreated(depositor.addr, address(expectedCapsule));
        emit StakedWithCapsule(depositor.addr, address(expectedCapsule));

        vm.startPrank(depositor.addr);
        clientGateway.stake{value: 32 ether}(abi.encodePacked(_getPubkey(validatorContainer)), bytes(""), bytes32(0));
        vm.stopPrank();

        // do some hack to replace expectedCapsule address with capsule address loaded from proof file
        // because capsule address is expected to be compatible with validator container withdrawal credentails
        address capsuleAddress = _getCapsuleFromWithdrawalCredentials(_getWithdrawalCredentials(validatorContainer));
        vm.etch(capsuleAddress, address(expectedCapsule).code);
        capsule = ExoCapsule(payable(capsuleAddress));
        stdstore.target(capsuleAddress).sig("_beacon()").checked_write(address(capsuleBeacon));
        assertEq(stdstore.target(capsuleAddress).sig("_beacon()").read_address(), address(capsuleBeacon));

        /// replace expectedCapsule with capsule
        bytes32 capsuleSlotInGateway = bytes32(
            stdstore.target(address(clientGatewayLogic)).sig("ownerToCapsule(address)").with_key(depositor.addr).find()
        );
        vm.store(address(clientGateway), capsuleSlotInGateway, bytes32(uint256(uint160(address(capsule)))));
        assertEq(address(clientGateway.ownerToCapsule(depositor.addr)), address(capsule));

        /// initialize replaced capsule
        capsule.initialize(address(clientGateway), depositor.addr, address(beaconOracle));

        // 2. next depositor call clientGateway.depositBeaconChainValidator to deposit into Exocore from client chain
        // through layerzero

        /// client chain layerzero endpoint should emit the message packet including deposit payload.
        uint64 depositRequestNonce = 1;
        uint256 depositAmount = uint256(_getEffectiveBalance(validatorContainer)) * GWEI_TO_WEI;
        bytes memory depositRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)),
            bytes32(bytes20(depositor.addr)),
            depositAmount
        );
        uint256 depositRequestNativeFee = clientGateway.quote(depositRequestPayload);
        bytes32 depositRequestId = generateUID(depositRequestNonce, true);

        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            depositRequestNonce,
            depositRequestPayload
        );

        /// client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_DEPOSIT, depositRequestId, depositRequestNonce, depositRequestNativeFee
        );

        /// call depositBeaconChainValidator to see if these events are emitted as expected
        vm.startPrank(depositor.addr);
        clientGateway.depositBeaconChainValidator{value: depositRequestNativeFee}(validatorContainer, validatorProof);
        vm.stopPrank();

        // 3. thirdly layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        /// exocore gateway should return response message to exocore network layerzero endpoint
        uint64 depositResponseNonce = 2;
        lastlyUpdatedPrincipalBalance += depositAmount;
        bytes memory depositResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, depositRequestNonce, true, lastlyUpdatedPrincipalBalance);
        uint256 depositResponseNativeFee = exocoreGateway.quote(clientChainId, depositResponsePayload);
        bytes32 depositResponseId = generateUID(depositResponseNonce, false);

        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            depositResponseNonce,
            depositResponsePayload
        );

        /// exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(
            GatewayStorage.Action.RESPOND, depositResponseId, depositResponseNonce, depositResponseNativeFee
        );

        /// relayer catches the request message packet by listening to client chain event and feed it to Exocore network
        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), depositRequestNonce),
            address(exocoreGateway),
            depositRequestId,
            depositRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        // At last layerzero relayers should watch the response message packet and relay the message back to source
        // chain endpoint

        /// client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositResult(true, VIRTUAL_STAKED_ETH_ADDRESS, depositor.addr, depositAmount);

        /// relayer catches the response message packet by listening to Exocore event and feed it to client chain
        vm.startPrank(relayer.addr);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), depositResponseNonce),
            address(clientGateway),
            depositResponseId,
            depositResponsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

    function _simulateBlockEnvironmentForNativeDeposit() internal {
        /// we set the timestamp of proof to be exactly the timestamp that the validator container get activated on
        /// beacon chain
        activationTimestamp = BEACON_CHAIN_GENESIS_TIME + _getActivationEpoch(validatorContainer) * SECONDS_PER_EPOCH;
        mockProofTimestamp = activationTimestamp;
        validatorProof.beaconBlockTimestamp = mockProofTimestamp;

        /// we set current block timestamp to be exactly one slot after the proof generation timestamp
        mockCurrentBlockTimestamp = mockProofTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);

        /// we mock the call beaconOracle.timestampToBlockRoot to return the expected block root in proof file
        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector),
            abi.encode(beaconBlockRoot)
        );
    }

    function _testNativeWithdraw(Player memory withdrawer, Player memory relayer, uint256 lastlyUpdatedPrincipalBalance)
        internal
    {
        // before native withdraw, we simulate proper block environment states to make proof valid
        _simulateBlockEnvironmentForNativeWithdraw();
        deal(address(capsule), 1 ether); // Deposit 1 ether to handle excess amount withdraw

        // 2. withdrawer will call clientGateway.processBeaconChainWithdrawal to withdraw from Exocore thru layerzero

        /// client chain layerzero endpoint should emit the message packet including deposit payload.
        uint64 withdrawRequestNonce = 3;
        uint64 withdrawalAmountGwei = _getWithdrawalAmount(withdrawalContainer);
        uint256 withdrawalAmount;
        if (withdrawalAmountGwei > MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR) {
            withdrawalAmount = MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR * GWEI_TO_WEI;
        } else {
            withdrawalAmount = withdrawalAmountGwei * GWEI_TO_WEI;
        }
        bytes memory withdrawRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE,
            bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)),
            bytes32(bytes20(withdrawer.addr)),
            withdrawalAmount
        );
        uint256 withdrawRequestNativeFee = clientGateway.quote(withdrawRequestPayload);
        bytes32 withdrawRequestId = generateUID(withdrawRequestNonce, true);

        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            withdrawRequestNonce,
            withdrawRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE,
            withdrawRequestId,
            withdrawRequestNonce,
            withdrawRequestNativeFee
        );

        vm.startPrank(withdrawer.addr);
        clientGateway.processBeaconChainWithdrawal{value: withdrawRequestNativeFee}(
            validatorContainer, validatorProof, withdrawalContainer, withdrawalProof
        );
        vm.stopPrank();

        /// exocore gateway should return response message to exocore network layerzero endpoint
        uint64 withdrawResponseNonce = 3;
        lastlyUpdatedPrincipalBalance -= withdrawalAmount;
        bytes memory withdrawResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, withdrawRequestNonce, true, lastlyUpdatedPrincipalBalance);
        uint256 withdrawResponseNativeFee = exocoreGateway.quote(clientChainId, withdrawResponsePayload);
        bytes32 withdrawResponseId = generateUID(withdrawResponseNonce, false);

        // exocore gateway should return response message to exocore network layerzero endpoint
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            withdrawResponseNonce,
            withdrawResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(
            GatewayStorage.Action.RESPOND, withdrawResponseId, withdrawResponseNonce, withdrawResponseNativeFee
        );
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), withdrawRequestNonce),
            address(exocoreGateway),
            withdrawRequestId,
            withdrawRequestPayload,
            bytes("")
        );

        // client chain gateway should execute the response hook and emit depositResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit WithdrawPrincipalResult(true, address(VIRTUAL_STAKED_ETH_ADDRESS), withdrawer.addr, withdrawalAmount);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), withdrawResponseNonce),
            address(clientGateway),
            withdrawResponseId,
            withdrawResponsePayload,
            bytes("")
        );
    }

    function _simulateBlockEnvironmentForNativeWithdraw() internal {
        // load beacon chain validator container and proof from json file
        string memory withdrawalInfo = vm.readFile("test/foundry/test-data/full_withdrawal_proof.json");
        _loadValidatorContainer(withdrawalInfo);
        // load withdrawal proof
        _loadWithdrawalContainer(withdrawalInfo);

        validatorProof.beaconBlockTimestamp = withdrawalProof.beaconBlockTimestamp + SECONDS_PER_SLOT;
        mockCurrentBlockTimestamp = validatorProof.beaconBlockTimestamp + SECONDS_PER_SLOT;
        vm.warp(mockCurrentBlockTimestamp);
        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector, validatorProof.beaconBlockTimestamp),
            abi.encode(beaconBlockRoot)
        );
        vm.mockCall(
            address(beaconOracle),
            abi.encodeWithSelector(beaconOracle.timestampToBlockRoot.selector, withdrawalProof.beaconBlockTimestamp),
            abi.encode(withdrawBeaconBlockRoot)
        );
    }

}
