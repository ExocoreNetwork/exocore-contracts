// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";

import {IVault} from "../interfaces/IVault.sol";
import {BaseRestakingController} from "./BaseRestakingController.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/// @title LSTRestakingController
/// @author ExocoreNetwork
/// @notice Implementation of ILSTRestakingController, used to restake tokens.
abstract contract LSTRestakingController is
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    ILSTRestakingController,
    BaseRestakingController
{

    /// @inheritdoc ILSTRestakingController
    function deposit(address token, uint256 amount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(amount)
        whenNotPaused
        nonReentrant
    {
        IVault vault = _getVault(token);
        vault.deposit(msg.sender, amount);

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), amount);
        bytes memory encodedRequest = abi.encode(token, msg.sender, amount);

        _processRequest(Action.REQUEST_DEPOSIT, actionArgs, encodedRequest);
    }

    /// @inheritdoc ILSTRestakingController
    function withdrawPrincipalFromExocore(address token, uint256 principalAmount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(principalAmount)
        whenNotPaused
        nonReentrant
    {
        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), principalAmount);
        bytes memory encodedRequest = abi.encode(token, msg.sender, principalAmount);

        _processRequest(Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE, actionArgs, encodedRequest);
    }

    /// @inheritdoc ILSTRestakingController
    function withdrawRewardFromExocore(address token, uint256 rewardAmount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(rewardAmount)
        whenNotPaused
        nonReentrant
    {
        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), rewardAmount);
        bytes memory encodedRequest = abi.encode(token, msg.sender, rewardAmount);
        _processRequest(Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE, actionArgs, encodedRequest);
    }

    /// @inheritdoc ILSTRestakingController
    function depositThenDelegateTo(address token, uint256 amount, string calldata operator)
        external
        payable
        override
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(operator)
        whenNotPaused
        nonReentrant
    {
        IVault vault = _getVault(token);
        vault.deposit(msg.sender, amount);

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), bytes(operator), amount);
        bytes memory encodedRequest = abi.encode(token, msg.sender, operator, amount);
        _processRequest(Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO, actionArgs, encodedRequest);
    }

}
