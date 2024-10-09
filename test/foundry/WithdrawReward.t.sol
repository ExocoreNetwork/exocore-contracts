pragma solidity ^0.8.19;

import "../../src/core/ExocoreGateway.sol";

import "../../src/interfaces/precompiles/IReward.sol";
import {Action, GatewayStorage} from "../../src/storage/GatewayStorage.sol";
import "../mocks/RewardMock.sol";
import "./ExocoreDeployer.t.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract WithdrawRewardTest is ExocoreDeployer {

    using AddressCast for address;

    event RewardOperation(
        bool isSubmitReward,
        bool indexed success,
        bytes32 indexed token,
        bytes32 indexed avsOrWithdrawer,
        uint256 amount
    );
    event Transfer(address indexed from, address indexed to, uint256 amount);

    uint256 constant DEFAULT_ENDPOINT_CALL_GAS_LIMIT = 200_000;

    function test_SubmitAndClaimAndWithdrawRewardByLayerZero() public {
        Player memory avsDepositor = players[0];
        Player memory staker = players[1];
        Player memory relayer = players[2];
        address avs = address(0xaabb);

        // fund the avs depositor some restake token so that it can deposit reward to reward vault
        vm.startPrank(exocoreValidatorSet.addr);
        restakeToken.transfer(avsDepositor.addr, 1_000_000);
        vm.stopPrank();

        // fund the depositor, staker, and exocore gateway for gas fee
        deal(avsDepositor.addr, 1e22);
        deal(staker.addr, 1e22);
        deal(address(exocoreGateway), 1e22);

        // the amount of deposit, distribute, and withdraw
        uint256 depositAmount = 1000;
        uint256 distributeAmount = 500;
        uint256 claimAmount = 100;
        uint256 withdrawAmount = 100;

        // before withdraw we should add whitelist tokens
        test_AddWhitelistTokens();

        _testSubmitReward(avsDepositor, relayer, staker, avs, depositAmount);
        RewardMock(REWARD_PRECOMPILE_ADDRESS).distributeReward(
            clientChainId,
            _addressToBytes(address(restakeToken)),
            _addressToBytes(avs),
            _addressToBytes(staker.addr),
            distributeAmount
        );
        _testClaimReward(staker, relayer, claimAmount);
        _testWithdrawReward(staker, withdrawAmount);
    }

    function _testSubmitReward(
        Player memory depositor,
        Player memory relayer,
        Player memory staker,
        address avs,
        uint256 amount
    ) internal {
        // -- submit reward workflow --

        // first user call client chain gateway to submit reward on behalf of AVS

        // depositor needs to approve the restake token to the client gateway
        vm.startPrank(depositor.addr);
        restakeToken.approve(address(rewardVault), amount);
        vm.stopPrank();

        // estimate l0 relay fee that the user should pay
        bytes memory submitRewardRequestPayload = abi.encodePacked(
            Action.REQUEST_SUBMIT_REWARD, bytes32(bytes20(address(restakeToken))), bytes32(bytes20(avs)), amount
        );
        uint256 requestNativeFee = clientGateway.quote(submitRewardRequestPayload);
        bytes32 requestId = generateUID(outboundNonces[clientChainId], true);

        // depositor should transfer deposited token to vault
        vm.expectEmit(true, true, false, true, address(restakeToken));
        emit Transfer(depositor.addr, address(rewardVault), amount);

        // client chain layerzero endpoint should emit the message packet including submit reward payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            outboundNonces[clientChainId],
            submitRewardRequestPayload
        );

        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(Action.REQUEST_SUBMIT_REWARD, requestId, outboundNonces[clientChainId]++, requestNativeFee);

        vm.startPrank(depositor.addr);
        clientGateway.submitReward{value: requestNativeFee}(address(restakeToken), avs, amount);
        vm.stopPrank();

        // assert that withdrawable amount is zero
        assertEq(rewardVault.getWithdrawableBalance(address(restakeToken), staker.addr), 0);
        assertEq(rewardVault.getWithdrawableBalance(address(restakeToken), depositor.addr), 0);
        // assert total deposited amount for the avs is equal to the amount
        assertEq(rewardVault.getTotalDepositedRewards(address(restakeToken), avs), amount);

        // second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        // exocore gateway should emit RewardOperation event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit RewardOperation(true, true, bytes32(bytes20(address(restakeToken))), bytes32(bytes20(avs)), amount);

        vm.expectEmit(address(exocoreGateway));
        emit MessageExecuted(Action.REQUEST_SUBMIT_REWARD, inboundNonces[exocoreChainId]++);

        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), inboundNonces[exocoreChainId] - 1),
            address(exocoreGateway),
            requestId,
            submitRewardRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        // assert that RewardMock has increased the reward amount for the avs
        assertEq(
            RewardMock(REWARD_PRECOMPILE_ADDRESS).getRewardAmountForAVS(
                clientChainId, _addressToBytes(address(restakeToken)), _addressToBytes(avs)
            ),
            amount
        );
    }

    function _testClaimReward(Player memory withdrawer, Player memory relayer, uint256 amount) internal {
        // -- claim reward workflow --

        uint256 withdrawableAmountBeforeClaim =
            rewardVault.getWithdrawableBalance(address(restakeToken), withdrawer.addr);

        // first user call client chain gateway to withdraw

        // estimate l0 relay fee that the user should pay
        bytes memory withdrawRequestPayload = abi.encodePacked(
            Action.REQUEST_CLAIM_REWARD,
            bytes32(bytes20(address(restakeToken))),
            bytes32(bytes20(withdrawer.addr)),
            amount
        );
        uint256 requestNativeFee = clientGateway.quote(withdrawRequestPayload);
        bytes32 requestId = generateUID(outboundNonces[clientChainId], true);
        // client chain layerzero endpoint should emit the message packet including withdraw payload.
        vm.expectEmit(true, true, true, true, address(clientChainLzEndpoint));
        emit NewPacket(
            exocoreChainId,
            address(clientGateway),
            address(exocoreGateway).toBytes32(),
            outboundNonces[clientChainId],
            withdrawRequestPayload
        );
        // client chain gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit MessageSent(Action.REQUEST_CLAIM_REWARD, requestId, outboundNonces[clientChainId]++, requestNativeFee);

        vm.startPrank(withdrawer.addr);
        clientGateway.claimRewardFromExocore{value: requestNativeFee}(address(restakeToken), amount);
        vm.stopPrank();

        // assert that withdrawable amount is not increased before receiving response from exocore
        assertEq(
            rewardVault.getWithdrawableBalance(address(restakeToken), withdrawer.addr), withdrawableAmountBeforeClaim
        );

        // second layerzero relayers should watch the request message packet and relay the message to destination
        // endpoint

        // exocore gateway should return response message to exocore network layerzero endpoint
        bytes memory withdrawResponsePayload = abi.encodePacked(Action.RESPOND, outboundNonces[clientChainId] - 1, true);
        uint256 responseNativeFee = exocoreGateway.quote(clientChainId, withdrawResponsePayload);
        bytes32 responseId = generateUID(outboundNonces[exocoreChainId], false);

        // exocore gateway should emit RewardOperation event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit RewardOperation(
            false, true, bytes32(bytes20(address(restakeToken))), bytes32(bytes20(withdrawer.addr)), amount
        );

        vm.expectEmit(true, true, true, true, address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            outboundNonces[exocoreChainId],
            withdrawResponsePayload
        );
        // exocore gateway should emit MessageSent event
        vm.expectEmit(true, true, true, true, address(exocoreGateway));
        emit MessageSent(Action.RESPOND, responseId, outboundNonces[exocoreChainId]++, responseNativeFee);

        vm.expectEmit(address(exocoreGateway));
        emit MessageExecuted(Action.REQUEST_CLAIM_REWARD, inboundNonces[exocoreChainId]++);

        vm.startPrank(relayer.addr);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), inboundNonces[exocoreChainId] - 1),
            address(exocoreGateway),
            requestId,
            withdrawRequestPayload,
            bytes("")
        );
        vm.stopPrank();

        // third layerzero relayers should watch the response message packet and relay the message to source chain
        // endpoint

        // client chain gateway should execute the response hook and emit RequestFinished event
        vm.expectEmit(true, true, true, true, address(clientGateway));
        emit ResponseProcessed(Action.REQUEST_CLAIM_REWARD, outboundNonces[clientChainId] - 1, true);

        vm.expectEmit(address(clientGateway));
        emit MessageExecuted(Action.RESPOND, inboundNonces[clientChainId]++);

        vm.startPrank(relayer.addr);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), inboundNonces[clientChainId] - 1),
            address(clientGateway),
            responseId,
            withdrawResponsePayload,
            bytes("")
        );
        vm.stopPrank();

        // assert that the withdrawable amount has been increased by the amount
        uint256 withdrawableAmountAfterClaim =
            rewardVault.getWithdrawableBalance(address(restakeToken), withdrawer.addr);
        assertEq(withdrawableAmountAfterClaim, withdrawableAmountBeforeClaim + amount);
    }

    function _testWithdrawReward(Player memory withdrawer, uint256 amount) internal {
        // -- withdraw reward workflow --

        uint256 withdrawableAmountBeforeWithdraw =
            rewardVault.getWithdrawableBalance(address(restakeToken), withdrawer.addr);
        uint256 balanceBeforeWithdraw = restakeToken.balanceOf(withdrawer.addr);

        vm.startPrank(withdrawer.addr);
        clientGateway.withdrawReward(address(restakeToken), withdrawer.addr, amount);
        vm.stopPrank();

        // assert the withdrawable amount has been decreased by the amount
        uint256 withdrawableAmountAfterWithdraw =
            rewardVault.getWithdrawableBalance(address(restakeToken), withdrawer.addr);
        assertEq(withdrawableAmountAfterWithdraw, withdrawableAmountBeforeWithdraw - amount);
        // assert that the balance of the withdrawer has been increased by the amount
        uint256 balanceAfterWithdraw = restakeToken.balanceOf(withdrawer.addr);
        assertEq(balanceAfterWithdraw, balanceBeforeWithdraw + amount);
    }

}
