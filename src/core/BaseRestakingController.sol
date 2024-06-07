pragma solidity ^0.8.19;

import {IBaseRestakingController} from "../interfaces/IBaseRestakingController.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IVault} from "../interfaces/IVault.sol";
import {MessagingFee, MessagingReceipt, OAppSenderUpgradeable} from "../lzApp/OAppSenderUpgradeable.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract BaseRestakingController is
    PausableUpgradeable,
    OAppSenderUpgradeable,
    IBaseRestakingController,
    ClientChainGatewayStorage
{

    using OptionsBuilder for bytes;

    receive() external payable {}

    function claim(address token, uint256 amount, address recipient)
        external
        isTokenWhitelisted(token)
        isValidAmount(amount)
        whenNotPaused
    {
        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = _getCapsule(msg.sender);
            capsule.withdraw(amount, payable(recipient));

            emit ClaimSucceeded(token, recipient, amount);
        } else {
            IVault vault = _getVault(token);
            vault.withdraw(msg.sender, recipient, amount);

            emit ClaimSucceeded(token, recipient, amount);
        }
    }

    function delegateTo(string calldata operator, address token, uint256 amount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(operator)
        whenNotPaused
    {
        _processRequest(token, msg.sender, amount, Action.REQUEST_DELEGATE_TO, operator);
    }

    function undelegateFrom(string calldata operator, address token, uint256 amount)
        external
        payable
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(operator)
        whenNotPaused
    {
        _processRequest(token, msg.sender, amount, Action.REQUEST_UNDELEGATE_FROM, operator);
    }

    function _processRequest(
        address token,
        address sender,
        uint256 amount,
        Action action,
        string memory operator // Optional parameter, empty string when not needed.
    ) internal {
        outboundNonce++;
        bool hasOperator = bytes(operator).length > 0;

        // Use a single abi.encode call via ternary operators to handle both cases.
        _registeredRequests[outboundNonce] =
            hasOperator ? abi.encode(token, operator, sender, amount) : abi.encode(token, sender, amount);

        _registeredRequestActions[outboundNonce] = action;

        // Use a single abi.encodePacked call via ternary operators to handle both cases.
        bytes memory actionArgs = hasOperator
            ? abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(sender)), bytes(operator), amount)
            : abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(sender)), amount);

        _sendMsgToExocore(action, actionArgs);
    }

    function _sendMsgToExocore(Action action, bytes memory actionArgs) internal {
        bytes memory payload = abi.encodePacked(action, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(EXOCORE_CHAIN_ID, payload, options, false);

        MessagingReceipt memory receipt = _lzSend(
            EXOCORE_CHAIN_ID, payload, options, MessagingFee(fee.nativeFee, 0), exocoreValidatorSetAddress, false
        );
        emit MessageSent(action, receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }

}
