pragma solidity ^0.8.19;

import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";
import "../../src/core/ExocoreGateway.sol";
import "../../src/storage/GatewayStorage.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";
import "../mocks/DelegationMock.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "forge-std/console.sol";

contract DelegateTest is ExocoreDeployer {
    using AddressCast for address;

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200000;

    event NewPacket(uint32, address, bytes32, uint64, bytes);
    event MessageSent(GatewayStorage.Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    event DelegateResult(
        bool indexed success, address indexed delegator, string delegatee, address token, uint256 amount
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

    function test_Delegation() public {
        Player memory delegator = players[0];
        Player memory relayer = players[1];
        string memory operatorAddress = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";

        deal(delegator.addr, 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 delegateAmount = 10000;

        _testDelegate(delegator.addr, relayer.addr, operatorAddress, delegateAmount);
    }

    function test_Undelegation() public {
        Player memory delegator = players[0];
        Player memory relayer = players[1];
        string memory operatorAddress = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";

        deal(delegator.addr, 1e22);
        deal(address(exocoreGateway), 1e22);
        uint256 delegateAmount = 10000;
        uint256 undelegateAmount = 5000;

        _testDelegate(delegator.addr, relayer.addr, operatorAddress, delegateAmount);
        _testUndelegate(delegator.addr, relayer.addr, operatorAddress, undelegateAmount);
    }

    function _testDelegate(address delegator, address relayer, string memory operator, uint256 delegateAmount) internal {
        /* ------------------------- delegate workflow test ------------------------- */

        // 1. first user call client chain gateway to delegate

        /// estimate the messaging fee that would be charged from user
        bytes memory delegateRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DELEGATE_TO,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator))),
            bytes(operator),
            delegateAmount
        );
        uint256 requestNativeFee = clientGateway.quote(delegateRequestPayload);
        bytes32 requestId = generateUID(uint64(1), true);

        /// layerzero endpoint should emit the message packet including delegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            uint64(1),
            delegateRequestPayload
        );

        /// clientGateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_DELEGATE_TO, requestId, uint64(1), requestNativeFee);

        /// delegator call clientGateway to send delegation request
        vm.startPrank(delegator);
        clientGateway.delegateTo{value: requestNativeFee}(operator, address(restakeToken), delegateAmount);
        vm.stopPrank();

        // 2. second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        bytes memory delegateResponsePayload = abi.encodePacked(GatewayStorage.Action.RESPOND, uint64(1), true);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, delegateResponsePayload);
        bytes32 responseId = generateUID(uint64(1), false);

        /// DelegationMock contract should receive correct message payload
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit DelegateRequestProcessed(
            uint16(clientChainId),
            uint64(1),
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator))),
            operator,
            delegateAmount
        );

        /// layerzero endpoint should emit the message packet including delegation response payload.
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(1),
            delegateResponsePayload
        );

        /// exocoreGateway should emit MessageSent event after finishing sending response
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, uint64(1), responseNativeFee);

        /// relayer call layerzero endpoint to deliver request messages and generate response message
        vm.startPrank(relayer);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(1)),
            address(exocoreGateway),
            requestId,
            delegateRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        /// assert that DelegationMock contract should have recorded the delegate
        uint256 actualDelegateAmount = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(delegator, operator, clientChainId, address(restakeToken));
        assertEq(actualDelegateAmount, delegateAmount);

        // 3. third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        /// after relayer relay the response message back to client chain, clientGateway should emit DelegateResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DelegateResult(true, delegator, operator, address(restakeToken), delegateAmount);

        /// relayer should watch the response message and relay it back to client chain
        vm.startPrank(relayer);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), uint64(1)),
            address(clientGateway),
            responseId,
            delegateResponsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

    function _testUndelegate(address delegator, address relayer, string memory operator, uint256 undelegateAmount) internal {
        /* ------------------------- undelegate workflow test ------------------------- */
        uint256 totalDelegate = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(delegator, operator, clientChainId, address(restakeToken));
        require(undelegateAmount <= totalDelegate, "undelegate amount overflow");

        // 1. first user call client chain gateway to undelegate

        /// estimate the messaging fee that would be charged from user
        bytes memory undelegateRequestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_UNDELEGATE_FROM,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator))),
            bytes(operator),
            undelegateAmount
        );
        uint256 requestNativeFee = clientGateway.quote(undelegateRequestPayload);
        bytes32 requestId = generateUID(2, true);

        /// layerzero endpoint should emit the message packet including undelegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            uint64(2),
            undelegateRequestPayload
        );

        /// clientGateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_UNDELEGATE_FROM, requestId, uint64(2), requestNativeFee);

        /// delegator call clientGateway to send undelegation request
        vm.startPrank(delegator);
        clientGateway.undelegateFrom{value: requestNativeFee}(operator, address(restakeToken), undelegateAmount);
        vm.stopPrank();

        // 2. second layerzero relayers should watch the request message packet and relay the message to destination endpoint

        bytes memory undelegateResponsePayload = abi.encodePacked(GatewayStorage.Action.RESPOND, uint64(2), true);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, undelegateResponsePayload);
        bytes32 responseId = generateUID(2, false);

        /// DelegationMock contract should receive correct message payload
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit UndelegateRequestProcessed(
            uint16(clientChainId),
            uint64(2),
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator))),
            operator,
            undelegateAmount
        );

        /// layerzero endpoint should emit the message packet including undelegation response payload.
        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(2),
            undelegateResponsePayload
        );

        /// exocoreGateway should emit MessageSent event after finishing sending response
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, uint64(2), responseNativeFee);

        /// relayer call layerzero endpoint to deliver request messages and generate response message
        vm.startPrank(relayer);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), uint64(2)),
            address(exocoreGateway),
            requestId,
            undelegateRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        /// assert that DelegationMock contract should have recorded the undelegation
        uint256 actualDelegateAmount = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(delegator, operator, clientChainId, address(restakeToken));
        assertEq(actualDelegateAmount, totalDelegate - undelegateAmount);

        // 3. third layerzero relayers should watch the response message packet and relay the message to source chain endpoint

        /// after relayer relay the response message back to client chain, clientGateway should emit UndelegateResult event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit UndelegateResult(true, delegator, operator, address(restakeToken), undelegateAmount);

        /// relayer should watch the response message and relay it back to client chain
        vm.startPrank(relayer);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), uint64(2)),
            address(clientGateway),
            responseId,
            undelegateResponsePayload,
            bytes("")
        );
        vm.stopPrank();
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
