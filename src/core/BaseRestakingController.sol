pragma solidity ^0.8.19;

import {IBaseRestakingController} from "../interfaces/IBaseRestakingController.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IVault} from "../interfaces/IVault.sol";
import {MessagingFee, MessagingReceipt, OAppSenderUpgradeable} from "../lzApp/OAppSenderUpgradeable.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";

import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

abstract contract BaseRestakingController is
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
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

    function _processRequest(Action action, bytes memory actionArgs, bytes memory encodedRequest) internal {
        outboundNonce++;
        _registeredRequests[outboundNonce] = encodedRequest;
        _registeredRequestActions[outboundNonce] = action;

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
