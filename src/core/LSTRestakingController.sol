pragma solidity ^0.8.19;

import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";

import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract LSTRestakingController is PausableUpgradeable, ILSTRestakingController, BaseRestakingController {
    function deposit(address token, uint256 amount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(amount)
        whenNotPaused
    {
        _processRequest(token, msg.sender, amount, Action.REQUEST_DEPOSIT, "");
    }

    function withdrawPrincipleFromExocore(address token, uint256 principleAmount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(principleAmount)
        whenNotPaused
    {
        _processRequest(token, msg.sender, principleAmount, Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE, "");
    }

    function withdrawRewardFromExocore(address token, uint256 rewardAmount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(rewardAmount)
        whenNotPaused
    {
        _processRequest(token, msg.sender, rewardAmount, Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE, "");
    }
}
