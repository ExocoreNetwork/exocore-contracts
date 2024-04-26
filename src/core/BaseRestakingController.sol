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

    modifier isTokenWhitelisted(address token) {
        require(whitelistTokens[token], "BaseRestakingController: token is not whitelisted");
        _;
    }

    modifier isValidAmount(uint256 amount) {
        require(amount > 0, "BaseRestakingController: amount should be greater than zero");
        _;
    }

    modifier vaultExists(address token) {
        require(address(tokenVaults[token]) != address(0), "BaseRestakingController: no vault added for this token");
        _;
    }

    modifier isValidBech32Address(string memory operator) {
        require(bytes(operator).length == 42, "BaseRestakingController: invalid bech32 address");
        _;
    }

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
        _getVault(token);
        registeredRequests[outboundNonce + 1] = abi.encode(token, operator, msg.sender, amount);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_DELEGATE_TO;

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), bytes(operator), amount);
        _sendMsgToExocore(Action.REQUEST_DELEGATE_TO, actionArgs);
    }

    function undelegateFrom(string calldata operator, address token, uint256 amount)
    external payable
    isTokenWhitelisted(token)
    isValidAmount(amount)
    isValidBech32Address(operator)
    whenNotPaused {
        _getVault(token);
        registeredRequests[outboundNonce + 1] = abi.encode(token, operator, msg.sender, amount);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_UNDELEGATE_FROM;

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), bytes(operator), amount);
        _sendMsgToExocore(Action.REQUEST_UNDELEGATE_FROM, actionArgs);
    }

    function _sendMsgToExocore(Action act, bytes memory actionArgs) internal {
        outboundNonce++;
        bytes memory payload = abi.encodePacked(act, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(exocoreChainId, payload, options, false);

        MessagingReceipt memory receipt =
            _lzSend(exocoreChainId, payload, options, MessagingFee(fee.nativeFee, 0), exocoreValidatorSetAddress, false);
        emit MessageSent(act, receipt.guid, receipt.nonce, receipt.fee.nativeFee);
    }
}
