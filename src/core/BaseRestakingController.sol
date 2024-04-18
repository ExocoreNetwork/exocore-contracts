pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {ITSSReceiver} from "../interfaces/ITSSReceiver.sol";
import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {OAppSenderUpgradeable, MessagingFee, MessagingReceipt} from "../lzApp/OAppSenderUpgradeable.sol";
import {ECDSA} from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";

abstract contract BaseRestakingController is PausableUpgradeable, OAppSenderUpgradeable, ClientChainGatewayStorage {
    using SafeERC20 for IERC20;
    using OptionsBuilder for bytes;

    receive() external payable {}

    function claim(address token, uint256 amount, address recipient) external whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(amount > 0, "Controller: amount should be greater than zero");

        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = ownerToCapsule[msg.sender];
            if (address(capsule) == address(0)) {
                revert CapsuleNotExistForOwner(msg.sender);
            }

            capsule.withdraw(amount, recipient);

            emit ClaimSucceeded(token, recipient, amount);
        } else {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

            vault.withdraw(msg.sender, recipient, amount);
            
            emit ClaimSucceeded(token, recipient, amount);
        }
    }

    function delegateTo(string calldata operator, address token, uint256 amount) external payable whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(amount > 0, "Controller: amount should be greater than zero");
        require(bytes(operator).length == 44, "Controller: invalid bech32 address");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        registeredRequests[outboundNonce + 1] = abi.encode(token, operator, msg.sender, amount);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_DELEGATE_TO;

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), bytes(operator), amount);
        _sendMsgToExocore(Action.REQUEST_DELEGATE_TO, actionArgs);
    }

    function undelegateFrom(string calldata operator, address token, uint256 amount) external payable whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(amount > 0, "Controller: amount should be greater than zero");
        require(bytes(operator).length == 42, "Controller: invalid bech32 address");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

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
