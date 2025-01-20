pragma solidity ^0.8.19;

import "../../src/core/ExocoreGateway.sol";

import "../../src/interfaces/precompiles/IDelegation.sol";
import {Action, GatewayStorage} from "../../src/storage/GatewayStorage.sol";
import "../mocks/DelegationMock.sol";
import "./ExocoreDeployer.t.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "forge-std/Test.sol";

contract DelegateTest is ExocoreDeployer {

    using AddressCast for address;

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200_000;

    Player delegator;
    Player relayer;

    string operatorAddress;

    event DelegationRequest(
        bool isDelegate,
        bool indexed accepted,
        bytes32 indexed token,
        bytes32 indexed delegator,
        string operator,
        uint256 amount
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
        _validateNonces();
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
        _validateNonces();
    }

    function _testDelegate(uint256 delegateAmount) internal {
        /* ------------------------- delegate workflow test ------------------------- */

        // 1. first user call client chain gateway to delegate

        /// estimate the messaging fee that would be charged from user
        bytes memory delegateRequestPayload = abi.encodePacked(
            Action.REQUEST_DELEGATE_TO,
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            delegateAmount,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            bytes(operatorAddress)
        );
        uint256 requestNativeFee = clientGateway.quote(delegateRequestPayload);
        bytes32 requestId = generateUID(outboundNonces[clientChainId], true);

        /// layerzero endpoint should emit the message packet including delegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            outboundNonces[clientChainId],
            delegateRequestPayload
        );

        /// clientGateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(Action.REQUEST_DELEGATE_TO, requestId, outboundNonces[clientChainId]++, requestNativeFee);

        /// delegator call clientGateway to send delegation request
        vm.startPrank(delegator.addr);
        clientGateway.delegateTo{value: requestNativeFee}(operatorAddress, address(restakeToken), delegateAmount);
        vm.stopPrank();

        // 2. second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        /// DelegationMock contract should receive correct message payload
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit DelegateRequestProcessed(
            clientChainId,
            outboundNonces[clientChainId] - 1,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            operatorAddress,
            delegateAmount
        );

        /// exocoreGateway contract should emit DelegateResult event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit DelegationRequest(
            true,
            true,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(delegator.addr)),
            operatorAddress,
            delegateAmount
        );

        vm.expectEmit(address(exocoreGateway));
        emit MessageExecuted(Action.REQUEST_DELEGATE_TO, inboundNonces[exocoreChainId]++);

        /// relayer call layerzero endpoint to deliver request messages and generate response message
        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), inboundNonces[exocoreChainId] - 1),
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
    }

    function _testUndelegate(uint256 undelegateAmount) internal {
        /* ------------------------- undelegate workflow test ------------------------- */
        uint256 totalDelegate = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(
            delegator.addr, operatorAddress, clientChainId, address(restakeToken)
        );
        require(undelegateAmount <= totalDelegate, "undelegate amount overflow");

        // 1. first user call client chain gateway to undelegate

        /// estimate the messaging fee that would be charged from user
        bytes memory undelegateRequestPayload = abi.encodePacked(
            Action.REQUEST_UNDELEGATE_FROM,
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            undelegateAmount,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            bytes(operatorAddress)
        );
        uint256 requestNativeFee = clientGateway.quote(undelegateRequestPayload);
        bytes32 requestId = generateUID(outboundNonces[clientChainId], true);

        /// layerzero endpoint should emit the message packet including undelegate payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            outboundNonces[clientChainId],
            undelegateRequestPayload
        );

        /// clientGateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(Action.REQUEST_UNDELEGATE_FROM, requestId, outboundNonces[clientChainId]++, requestNativeFee);

        /// delegator call clientGateway to send undelegation request
        vm.startPrank(delegator.addr);
        clientGateway.undelegateFrom{value: requestNativeFee}(operatorAddress, address(restakeToken), undelegateAmount);
        vm.stopPrank();

        // 2. second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        /// DelegationMock contract should receive correct message payload
        vm.expectEmit(true, true, true, true, DELEGATION_PRECOMPILE_ADDRESS);
        emit UndelegateRequestProcessed(
            clientChainId,
            outboundNonces[clientChainId] - 1,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator.addr))),
            operatorAddress,
            undelegateAmount
        );

        /// exocoreGateway contract should emit UndelegateResult event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit DelegationRequest(
            false,
            true,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(delegator.addr)),
            operatorAddress,
            undelegateAmount
        );

        vm.expectEmit(address(exocoreGateway));
        emit MessageExecuted(Action.REQUEST_UNDELEGATE_FROM, inboundNonces[exocoreChainId]++);

        /// relayer call layerzero endpoint to deliver request messages and generate response message
        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), inboundNonces[exocoreChainId] - 1),
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
    }

}
