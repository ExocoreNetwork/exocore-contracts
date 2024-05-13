pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {OAppSenderUpgradeable, MessagingFee, MessagingReceipt} from "../lzApp/OAppSenderUpgradeable.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IBaseRestakingController} from "../interfaces/IBaseRestakingController.sol";

import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";


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
    whenNotPaused {
        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = _getCapsule(msg.sender);
            capsule.withdraw(amount, recipient);

            emit ClaimSucceeded(token, recipient, amount);
        } else {
            IVault vault = _getVault(token);
            vault.withdraw(msg.sender, recipient, amount);

            emit ClaimSucceeded(token, recipient, amount);
        }
    }

    function delegateTo(string calldata operator, address token, uint256 amount)
    external payable
    isTokenWhitelisted(token)
    isValidAmount(amount)
    isValidBech32Address(operator)
    whenNotPaused {
        _processRequest(token, msg.sender, amount, Action.REQUEST_DELEGATE_TO, operator);

    }

    function undelegateFrom(string calldata operator, address token, uint256 amount)
    external payable
    isTokenWhitelisted(token)
    isValidAmount(amount)
    isValidBech32Address(operator)
    whenNotPaused {
        _processRequest(token, msg.sender, amount, Action.REQUEST_UNDELEGATE_FROM, operator);

    }

    function _processRequest(
        address token,
        address sender,
        uint256 amount,
        Action action,
        string memory operator // Optional parameter, you can pass an empty string if you don't need it.
    ) internal {
        if (token != VIRTUAL_STAKED_ETH_ADDRESS) {
            IVault vault = _getVault(token);
            // Logic specific to the REQUEST_DEPOSIT action
            if (action == Action.REQUEST_DEPOSIT  && bytes(operator).length == 0) {
                vault.deposit(sender, amount);
            }
        }
        outboundNonce++;
        // Determine how to code _registeredRequests based on whether or not an operator is provided
        if (bytes(operator).length > 0) {
            _registeredRequests[outboundNonce] = abi.encode(token, operator, sender, amount);
        } else {
            _registeredRequests[outboundNonce] = abi.encode(token, sender, amount);
        }
        _registeredRequestActions[outboundNonce] = action;
        // Consider whether operator is empty when building actionArgs
        bytes memory actionArgs;
        if (bytes(operator).length > 0) {
            actionArgs = abi.encodePacked(
                bytes32(bytes20(token)),
                bytes32(bytes20(sender)),
                bytes(operator),
                amount
            );
        } else {
            actionArgs = abi.encodePacked(
                bytes32(bytes20(token)),
                bytes32(bytes20(sender)),
                amount
            );
        }
        _sendMsgToExocore(action, actionArgs);
    }
    function _sendMsgToExocore(Action action, bytes memory actionArgs) internal {
        bytes memory payload = abi.encodePacked(action, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(exocoreChainId, payload, options, false);

        MessagingReceipt memory receipt = _lzSend(exocoreChainId, payload, options, MessagingFee(fee.nativeFee, 0), exocoreValidatorSetAddress, false);
        emit MessageSent(action, receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }
}
