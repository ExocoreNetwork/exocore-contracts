pragma solidity ^0.8.19;

import "../../src/core/ExocoreGateway.sol";

import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/storage/GatewayStorage.sol";
import "../mocks/DelegationMock.sol";
import "./ExocoreDeployer.t.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "forge-std/Test.sol";

import "forge-std/console.sol";

contract DelegateTest is ExocoreDeployer {

    using AddressCast for address;

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200_000;

    Player delegator;
    Player relayer;

    string operatorAddress;

    event DelegateResult(
        bool indexed success, address indexed delegator, string indexed delegatee, address token, uint256 amount
    );
    event UndelegateResult(
        bool indexed success, address indexed undelegator, string indexed undelegatee, address token, uint256 amount
    );
    event DelegateRequestProcessed(
        uint32 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );
    event UndelegateRequestProcessed(
        uint32 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );

    function setUp() public override {
        super.setUp();

        delegator = players[0];
        relayer = players[1];

        operatorAddress = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
    }

    function test_Delegation() public {
        deal(delegator.addr, 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 delegateAmount = 10_000;

        // before delegate we should add whitelist tokens
        test_AddWhitelistTokens();

        _testDelegate(delegateAmount);
    }

    function test_Undelegation() public {
        deal(delegator.addr, 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 delegateAmount = 10_000;
        uint256 undelegateAmount = 5000;

        // before undelegate we should add whitelist tokens
        test_AddWhitelistTokens();

        _testDelegate(delegateAmount);
        _testUndelegate(undelegateAmount);
    }

    function _testDelegate(uint256 delegateAmount) internal {
        /* ------------------------- delegate workflow test ------------------------- */

        // 1. first user call client chain gateway to delegate

        /// estimate the messaging fee that would be charged from user
        uint64 delegateRequestNonce = 2;
        bytes memory delegateRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DELEGATE_TO,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            bytes(operatorAddress),
            delegateAmount
        );
        uint256 requestNativeFee = clientGateway.quote(delegateRequestPayload);
        bytes32 requestId = generateUID(delegateRequestNonce, true);

        /// layerzero endpoint should emit the message packet including delegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            delegateRequestNonce,
            delegateRequestPayload
        );

        /// clientGateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_DELEGATE_TO, requestId, delegateRequestNonce, requestNativeFee);

        /// delegator call clientGateway to send delegation request
        vm.startPrank(delegator.addr);
        clientGateway.delegateTo{value: requestNativeFee}(operatorAddress, address(restakeToken), delegateAmount);
        vm.stopPrank();

        // 2. second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        uint64 delegateResponseNonce = 2;
        bytes memory delegateResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, delegateRequestNonce, true);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, delegateResponsePayload);
        bytes32 responseId = generateUID(delegateResponseNonce, false);

        /// DelegationMock contract should receive correct message payload
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit DelegateRequestProcessed(
            uint16(clientChainId),
            delegateRequestNonce,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            operatorAddress,
            delegateAmount
        );

        /// layerzero endpoint should emit the message packet including delegation response payload.
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            delegateResponseNonce,
            delegateResponsePayload
        );

        /// exocoreGateway should emit MessageSent event after finishing sending response
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, delegateResponseNonce, responseNativeFee);

        /// relayer call layerzero endpoint to deliver request messages and generate response message
        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), delegateRequestNonce),
            address(exocoreGateway),
            requestId,
            delegateRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        /// assert that DelegationMock contract should have recorded the delegate
        uint256 actualDelegateAmount = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(
            delegator.addr, operatorAddress, clientChainId, address(restakeToken)
        );
        assertEq(actualDelegateAmount, delegateAmount);

        // 3. third layerzero relayers should watch the response message packet and relay the message to source chain
        // endpoint

        /// after relayer relay the response message back to client chain, clientGateway should emit DelegateResult
        /// event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DelegateResult(true, delegator.addr, operatorAddress, address(restakeToken), delegateAmount);

        /// relayer should watch the response message and relay it back to client chain
        vm.startPrank(relayer.addr);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), delegateResponseNonce),
            address(clientGateway),
            responseId,
            delegateResponsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

    function _testUndelegate(uint256 undelegateAmount) internal {
        /* ------------------------- undelegate workflow test ------------------------- */
        uint256 totalDelegate = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(
            delegator.addr, operatorAddress, clientChainId, address(restakeToken)
        );
        require(undelegateAmount <= totalDelegate, "undelegate amount overflow");

        // 1. first user call client chain gateway to undelegate

        /// estimate the messaging fee that would be charged from user
        uint64 undelegateRequestNonce = 3;
        bytes memory undelegateRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_UNDELEGATE_FROM,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            bytes(operatorAddress),
            undelegateAmount
        );
        uint256 requestNativeFee = clientGateway.quote(undelegateRequestPayload);
        bytes32 requestId = generateUID(undelegateRequestNonce, true);

        /// layerzero endpoint should emit the message packet including undelegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            undelegateRequestNonce,
            undelegateRequestPayload
        );

        /// clientGateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_UNDELEGATE_FROM, requestId, undelegateRequestNonce, requestNativeFee
        );

        /// delegator call clientGateway to send undelegation request
        vm.startPrank(delegator.addr);
        clientGateway.undelegateFrom{value: requestNativeFee}(operatorAddress, address(restakeToken), undelegateAmount);
        vm.stopPrank();

        // 2. second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        uint64 undelegateResponseNonce = 3;
        bytes memory undelegateResponsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, undelegateRequestNonce, true);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, undelegateResponsePayload);
        bytes32 responseId = generateUID(undelegateResponseNonce, false);

        /// DelegationMock contract should receive correct message payload
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit UndelegateRequestProcessed(
            uint16(clientChainId),
            undelegateRequestNonce,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            operatorAddress,
            undelegateAmount
        );

        /// layerzero endpoint should emit the message packet including undelegation response payload.
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            undelegateResponseNonce,
            undelegateResponsePayload
        );

        /// exocoreGateway should emit MessageSent event after finishing sending response
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, undelegateResponseNonce, responseNativeFee);

        /// relayer call layerzero endpoint to deliver request messages and generate response message
        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), undelegateRequestNonce),
            address(exocoreGateway),
            requestId,
            undelegateRequestPayload,
            bytes("")
        );
        vm.stopPrank();
        /// assert that DelegationMock contract should have recorded the undelegation
        uint256 actualDelegateAmount = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(
            delegator.addr, operatorAddress, clientChainId, address(restakeToken)
        );
        assertEq(actualDelegateAmount, totalDelegate - undelegateAmount);

        // 3. third layerzero relayers should watch the response message packet and relay the message to source chain
        // endpoint

        /// after relayer relay the response message back to client chain, clientGateway should emit UndelegateResult
        /// event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit UndelegateResult(true, delegator.addr, operatorAddress, address(restakeToken), undelegateAmount);

        /// relayer should watch the response message and relay it back to client chain
        vm.startPrank(relayer.addr);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), undelegateResponseNonce),
            address(clientGateway),
            responseId,
            undelegateResponsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

}
