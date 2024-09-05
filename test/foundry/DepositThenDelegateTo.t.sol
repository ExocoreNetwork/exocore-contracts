pragma solidity ^0.8.19;

import "../../src/core/ExocoreGateway.sol";

import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/storage/GatewayStorage.sol";

import "../mocks/AssetsMock.sol";
import "../mocks/DelegationMock.sol";
import "./ExocoreDeployer.t.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "forge-std/Test.sol";

import "forge-std/console.sol";

contract DepositThenDelegateToTest is ExocoreDeployer {

    using AddressCast for address;

    // ExocoreGateway emits these two events after handling the request
    event DepositResult(bool indexed success, bytes32 indexed token, bytes32 indexed depositor, uint256 amount);
    event DelegateResult(
        bool indexed success, bytes32 indexed token, bytes32 indexed delegator, string operator, uint256 amount
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

        uint64 requestLzNonce = 1;
        uint64 responseLzNonce = 3; // 2 tokens are whitelisted, 3 is response
        uint256 delegateAmount = 10_000;

        // before all operations we should add whitelist tokens
        test_AddWhitelistTokens();

        // ensure there is enough balance
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(delegator, delegateAmount);
        vm.stopPrank();

        // approve it
        vm.startPrank(delegator);
        restakeToken.approve(address(vault), delegateAmount);
        vm.stopPrank();

        (bytes32 requestId, bytes memory requestPayload) =
            _testRequest(delegator, operatorAddress, requestLzNonce, delegateAmount);
        _testResponse(
            requestId,
            requestPayload,
            delegator,
            relayer,
            operatorAddress,
            requestLzNonce,
            responseLzNonce,
            delegateAmount
        );
    }

    function test_BalanceUpdatedWhen_DepositThenDelegateToResponseNotSuccess() public {
        address delegator = players[0].addr;
        address relayer = players[1].addr;
        string memory operatorAddress = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";

        deal(delegator, 1e22);
        deal(address(exocoreGateway), 1e22);

        uint64 requestLzNonce = 1;
        uint64 responseLzNonce = 3;
        uint256 delegateAmount = 10_000;

        // before all operations we should add whitelist tokens
        test_AddWhitelistTokens();

        // ensure there is enough balance
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(delegator, delegateAmount);
        vm.stopPrank();

        // approve it
        vm.startPrank(delegator);
        restakeToken.approve(address(vault), delegateAmount);
        vm.stopPrank();

        (bytes32 requestId, bytes memory requestPayload) =
            _testRequest(delegator, operatorAddress, requestLzNonce, delegateAmount);
        _testFailureResponse(delegator, relayer, requestLzNonce, responseLzNonce, delegateAmount);
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
        uint64 requestLzNonce,
        uint64 responseLzNonce,
        uint256 delegateAmount
    ) private {
        bytes memory responsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, requestLzNonce, true, delegateAmount);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, responsePayload);
        bytes32 responseId = generateUID(responseLzNonce, false);

        // deposit request is firstly handled and its event is firstly emitted
        vm.expectEmit(address(exocoreGateway));
        emit DepositResult(true, bytes32(bytes20(address(restakeToken))), bytes32(bytes20(delegator)), delegateAmount);

        // secondly delegate request is handled
        vm.expectEmit(DELEGATION_PRECOMPILE_ADDRESS);
        emit DelegateRequestProcessed(
            clientChainId,
            requestLzNonce,
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
            responseLzNonce, // outbound nonce not inbound, only equals because it's the first tx
            responsePayload
        );

        vm.expectEmit(address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, responseLzNonce, responseNativeFee);

        vm.expectEmit(address(exocoreGateway));
        emit DelegateResult(
            true, bytes32(bytes20(address(restakeToken))), bytes32(bytes20(delegator)), operatorAddress, delegateAmount
        );

        vm.startPrank(relayer);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), requestLzNonce),
            address(exocoreGateway),
            requestId,
            requestPayload,
            bytes("")
        );
        vm.stopPrank();

        uint256 actualDepositAmount = AssetsMock(ASSETS_PRECOMPILE_ADDRESS).getPrincipalBalance(
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
        emit RequestFinished(GatewayStorage.Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO, requestLzNonce, true);

        vm.startPrank(relayer);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), responseLzNonce),
            address(clientGateway),
            responseId,
            responsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

    function _testFailureResponse(
        address delegator,
        address relayer,
        uint64 requestLzNonce,
        uint64 responseLzNonce,
        uint256 delegateAmount
    ) private {
        // we assume delegation failed for some reason
        bool delegateSuccess = false;
        bytes memory responsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, requestLzNonce, delegateSuccess, delegateAmount);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, responsePayload);
        bytes32 responseId = generateUID(responseLzNonce, false);

        // request finished with successful deposit and failed delegation
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit RequestFinished(GatewayStorage.Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO, requestLzNonce, delegateSuccess);

        vm.startPrank(relayer);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), responseLzNonce),
            address(clientGateway),
            responseId,
            responsePayload,
            bytes("")
        );
        vm.stopPrank();

        // though delegation has failed, the principal balance for delegator should be updated
        assertEq(vault.principalBalances(delegator), delegateAmount);
    }

}
