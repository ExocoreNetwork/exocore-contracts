pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {IVault} from "../interfaces/IVault.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";

import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract LSTRestakingController is
    PausableUpgradeable,
    ILSTRestakingController,
    BaseRestakingController {
    function deposit(address token, uint256 amount) external payable isTokenWhitelisted(token) isValidAmount(amount) whenNotPaused {
        IVault vault = _getVault(token);
        vault.deposit(msg.sender, amount);
        _registeredRequests[outboundNonce + 1] = abi.encode(token, msg.sender, amount);
        _registeredRequestActions[outboundNonce + 1] = Action.REQUEST_DEPOSIT;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), amount);
        _sendMsgToExocore(Action.REQUEST_DEPOSIT, actionArgs);
    }

    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external payable isTokenWhitelisted(token) isValidAmount(principleAmount) whenNotPaused {
        _getVault(token);
        _registeredRequests[outboundNonce + 1] = abi.encode(token, msg.sender, principleAmount);
        _registeredRequestActions[outboundNonce + 1] = Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE;

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), principleAmount);
        _sendMsgToExocore(Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE, actionArgs);
    }

    function withdrawRewardFromExocore(address token, uint256 rewardAmount) external payable isTokenWhitelisted(token) isValidAmount(rewardAmount) whenNotPaused {
        _getVault(token);
        _registeredRequests[outboundNonce + 1] = abi.encode(token, msg.sender, rewardAmount);
        _registeredRequestActions[outboundNonce + 1] = Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), rewardAmount);
        _sendMsgToExocore(Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE, actionArgs);
    }

    function updateUsersBalances(UserBalanceUpdateInfo[] calldata info) public whenNotPaused {
        require(msg.sender == address(this), "LSTRestakingController: caller must be client chain gateway itself");
        for (uint256 i = 0; i < info.length; i++) {
            UserBalanceUpdateInfo memory userBalanceUpdate = info[i];
            for (uint256 j = 0; j < userBalanceUpdate.tokenBalances.length; j++) {
                TokenBalanceUpdateInfo memory tokenBalanceUpdate = userBalanceUpdate.tokenBalances[j];
                require(whitelistTokens[tokenBalanceUpdate.token], "Controller: token is not whitelisted");
                IVault vault = _getVault(tokenBalanceUpdate.token);

                if (tokenBalanceUpdate.lastlyUpdatedPrincipleBalance > 0) {
                    vault.updatePrincipleBalance(
                        userBalanceUpdate.user, tokenBalanceUpdate.lastlyUpdatedPrincipleBalance
                    );
                }

                if (tokenBalanceUpdate.lastlyUpdatedRewardBalance > 0) {
                    vault.updateRewardBalance(userBalanceUpdate.user, tokenBalanceUpdate.lastlyUpdatedRewardBalance);
                }

                if (tokenBalanceUpdate.unlockPrincipleAmount > 0 || tokenBalanceUpdate.unlockRewardAmount > 0) {
                    vault.updateWithdrawableBalance(
                        userBalanceUpdate.user,
                        tokenBalanceUpdate.unlockPrincipleAmount,
                        tokenBalanceUpdate.unlockRewardAmount
                    );
                }
            }
        }
    }
}
