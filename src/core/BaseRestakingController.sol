// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IBaseRestakingController} from "../interfaces/IBaseRestakingController.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IVault} from "../interfaces/IVault.sol";
import {MessagingFee, MessagingReceipt, OAppSenderUpgradeable} from "../lzApp/OAppSenderUpgradeable.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/// @title BaseRestakingController
/// @author ExocoreNetwork
/// @notice The base contract for the restaking controller. It only controls ERC20 tokens.
/// @dev This contract is abstract because it does not call the base contract's constructor. It is not used by
/// Bootstrap.
abstract contract BaseRestakingController is
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    OAppSenderUpgradeable,
    IBaseRestakingController,
    ClientChainGatewayStorage
{

    using OptionsBuilder for bytes;

    receive() external payable {}

    /// @inheritdoc IBaseRestakingController
    function claim(address token, uint256 amount, address recipient)
        external
        isTokenWhitelisted(token)
        isValidAmount(amount)
        whenNotPaused
        nonReentrant
    {
        require(recipient != address(0), "BaseRestakingController: recipient address cannot be empty or zero address");
        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = _getCapsule(msg.sender);
            capsule.withdraw(amount, payable(recipient));
        } else {
            IVault vault = _getVault(token);
            vault.withdraw(msg.sender, recipient, amount);
        }

        emit ClaimSucceeded(token, recipient, amount);
    }

    /// @inheritdoc IBaseRestakingController
    function delegateTo(string calldata operator, address token, uint256 amount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(operator)
        whenNotPaused
        nonReentrant
    {
        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), bytes(operator), amount);
        bytes memory encodedRequest = abi.encode(token, msg.sender, operator, amount);
        _processRequest(Action.REQUEST_DELEGATE_TO, actionArgs, encodedRequest);
    }

    /// @inheritdoc IBaseRestakingController
    function undelegateFrom(string calldata operator, address token, uint256 amount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(operator)
        whenNotPaused
        nonReentrant
    {
        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), bytes(operator), amount);
        bytes memory encodedRequest = abi.encode(token, msg.sender, operator, amount);
        _processRequest(Action.REQUEST_UNDELEGATE_FROM, actionArgs, encodedRequest);
    }

    /// @dev Processes the request by sending it to Exocore.
    /// @param action The action to be performed.
    /// @param actionArgs The encodePacked arguments for the action.
    /// @param encodedRequest The encoded request.
    function _processRequest(Action action, bytes memory actionArgs, bytes memory encodedRequest) internal {
        uint64 requestNonce = _sendMsgToExocore(action, actionArgs);

        _registeredRequests[requestNonce] = encodedRequest;
        _registeredRequestActions[requestNonce] = action;
    }

    /// @dev Sends a message to Exocore.
    /// @param action The action to be performed.
    /// @param actionArgs The encodePacked arguments for the action.
    function _sendMsgToExocore(Action action, bytes memory actionArgs) internal returns (uint64) {
        bytes memory payload = abi.encodePacked(action, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(EXOCORE_CHAIN_ID, payload, options, false);

        MessagingReceipt memory receipt =
            _lzSend(EXOCORE_CHAIN_ID, payload, options, MessagingFee(fee.nativeFee, 0), msg.sender, false);
        emit MessageSent(action, receipt.guid, receipt.nonce, receipt.fee.nativeFee);

        return receipt.nonce;
    }

}
