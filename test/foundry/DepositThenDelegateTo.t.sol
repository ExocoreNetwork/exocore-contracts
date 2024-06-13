pragma solidity ^0.8.19;

import "../../src/core/ExocoreGateway.sol";

import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/storage/GatewayStorage.sol";
import "../mocks/DelegationMock.sol";
import {DepositMock} from "../mocks/DepositMock.sol";
import "./ExocoreDeployer.t.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import "forge-std/Test.sol";

import "forge-std/console.sol";

contract DepositThenDelegateToTest is ExocoreDeployer {

    using AddressCast for address;

    // layer zero events
    event NewPacket(uint32, address, bytes32, uint64, bytes);
    event MessageSent(GatewayStorage.Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    // ClientChainGateway emits this when receiving the response
    event DepositThenDelegateResult(
        bool indexed delegateSuccess,
        address indexed delegator,
        string indexed delegatee,
        address token,
        uint256 delegatedAmount
    );

    // emitted by the mock delegation contract
    event DelegateRequestProcessed(
        uint32 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );

    function test_DepositThenDelegateTo() public {
        address delegator = players[0].addr;
        address relayer = players[1].addr;
        string memory operatorAddress = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";

        deal(delegator, 1e22);
        deal(address(exocoreGateway), 1e22);

        uint64 lzNonce = 1;
        uint256 delegateAmount = 10_000;

        // ensure there is enough balance
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(delegator, delegateAmount);
        vm.stopPrank();

        // approve it
        vm.startPrank(delegator);
        restakeToken.approve(address(vault), delegateAmount);
        vm.stopPrank();

        (bytes32 requestId, bytes memory requestPayload) =
            _testRequest(delegator, operatorAddress, lzNonce, delegateAmount);
        _testResponse(requestId, requestPayload, delegator, relayer, operatorAddress, lzNonce, delegateAmount);
    }

    function _testRequest(address delegator, string memory operatorAddress, uint64 lzNonce, uint256 delegateAmount)
        private
        returns (bytes32 requestId, bytes memory requestPayload)
    {
        uint256 beforeBalanceDelegator = restakeToken.balanceOf(delegator);
        uint256 beforeBalanceVault = restakeToken.balanceOf(address(vault));

        requestPayload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator))),
            bytes(operatorAddress),
            delegateAmount
        );
        uint256 requestNativeFee = clientGateway.quote(requestPayload);
        requestId = generateUID(lzNonce, true);

        vm.expectEmit(address(restakeToken));
        emit IERC20.Transfer(delegator, address(vault), delegateAmount);

        vm.expectEmit(address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId, address(clientGateway), address(exocoreGateway).toBytes32(), lzNonce, requestPayload
        );

        vm.expectEmit(address(clientGateway));
        emit MessageSent(GatewayStorage.Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO, requestId, lzNonce, requestNativeFee);

        vm.startPrank(delegator);
        clientGateway.depositThenDelegateTo{value: requestNativeFee}(
            address(restakeToken), delegateAmount, operatorAddress
        );
        vm.stopPrank();

        // check that the balance changed
        uint256 afterBalanceDelegator = restakeToken.balanceOf(delegator);
        assertEq(afterBalanceDelegator, beforeBalanceDelegator - delegateAmount);
        uint256 afterBalanceVault = restakeToken.balanceOf(address(vault));
        assertEq(afterBalanceVault, beforeBalanceVault + delegateAmount);
    }

    // even though this function is called _testResponse, it also tests
    // the receipt of an LZ packet on Exocore and then tests its response
    function _testResponse(
        bytes32 requestId,
        bytes memory requestPayload,
        address delegator,
        address relayer,
        string memory operatorAddress,
        uint64 lzNonce,
        uint256 delegateAmount
    ) private {
        bytes memory responsePayload = abi.encodePacked(GatewayStorage.Action.RESPOND, lzNonce, true, delegateAmount);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, responsePayload);
        bytes32 responseId = generateUID(lzNonce, false);

        vm.expectEmit(DELEGATION_PRECOMPILE_ADDRESS);
        emit DelegateRequestProcessed(
            clientChainId,
            lzNonce,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator))),
            operatorAddress,
            delegateAmount
        );

        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        // nothing indexed here
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            uint64(1), // outbound nonce not inbound, only equals because it's the first tx
            responsePayload
        );

        vm.expectEmit(address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, lzNonce, responseNativeFee);

        vm.startPrank(relayer);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), lzNonce),
            address(exocoreGateway),
            requestId,
            requestPayload,
            bytes("")
        );
        vm.stopPrank();

        uint256 actualDepositAmount = DepositMock(DEPOSIT_PRECOMPILE_ADDRESS).principleBalances(
            clientChainId,
            // weirdly, the address(x).toBytes32() did not work here.
            // for reference, the results are
            // addressOg = 0x0000000000000000000000000000000000000001
            // toBytes32 = 0x0000000000000000000000000000000000000000000000000000000000000001
            // abiEncode = 0x0000000000000000000000000000000000000001000000000000000000000000
            // so, AddressCast left pads it while abi.encodePacked is right padding it.
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(delegator)))
        );
        assertEq(actualDepositAmount, delegateAmount);

        uint256 actualDelegateAmount = DelegationMock(DELEGATION_PRECOMPILE_ADDRESS).getDelegateAmount(
            delegator, operatorAddress, clientChainId, address(restakeToken)
        );
        assertEq(actualDelegateAmount, delegateAmount);

        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit DepositThenDelegateResult(true, delegator, operatorAddress, address(restakeToken), delegateAmount);

        vm.startPrank(relayer);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), lzNonce),
            address(clientGateway),
            responseId,
            responsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

}
