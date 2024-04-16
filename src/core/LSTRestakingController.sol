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

abstract contract LSTRestakingController is PausableUpgradeable, OAppSenderUpgradeable, ClientChainGatewayStorage, ILSTRestakingController {
    using SafeERC20 for IERC20;
    using OptionsBuilder for bytes;

    receive() external payable {}

    function deposit(address token, uint256 amount) external payable whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(amount > 0, "Controller: amount should be greater than zero");

        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "Controller: no vault added for this token");

        vault.deposit(msg.sender, amount);

        registeredRequests[outboundNonce + 1] = abi.encode(token, msg.sender, amount);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_DEPOSIT;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), amount);
        _sendInterchainMsg(Action.REQUEST_DEPOSIT, actionArgs);
    }

    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external payable whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(principleAmount > 0, "Controller: amount should be greater than zero");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        registeredRequests[outboundNonce + 1] = abi.encode(token, msg.sender, principleAmount);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE;

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), principleAmount);
        _sendInterchainMsg(Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE, actionArgs);
    }

    function withdrawRewardFromExocore(address token, uint256 rewardAmount) external payable whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(rewardAmount > 0, "Controller: amount should be greater than zero");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        registeredRequests[outboundNonce + 1] = abi.encode(token, msg.sender, rewardAmount);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), rewardAmount);
        _sendInterchainMsg(Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE, actionArgs);
    }

    function claim(address token, uint256 amount, address recipient) external whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(amount > 0, "Controller: amount should be greater than zero");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        vault.withdraw(msg.sender, recipient, amount);
    }

    function updateUsersBalances(UserBalanceUpdateInfo[] calldata info) public whenNotPaused {
        require(msg.sender == address(this), "Controller: caller must be client chain gateway itself");
        for (uint256 i = 0; i < info.length; i++) {
            UserBalanceUpdateInfo memory userBalanceUpdate = info[i];
            for (uint256 j = 0; j < userBalanceUpdate.tokenBalances.length; j++) {
                TokenBalanceUpdateInfo memory tokenBalanceUpdate = userBalanceUpdate.tokenBalances[j];
                require(whitelistTokens[tokenBalanceUpdate.token], "Controller: token is not whitelisted");

                IVault vault = tokenVaults[tokenBalanceUpdate.token];
                if (address(vault) == address(0)) {
                    revert VaultNotExist();
                }

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
        _sendInterchainMsg(Action.REQUEST_DELEGATE_TO, actionArgs);
    }

    function undelegateFrom(string calldata operator, address token, uint256 amount) external payable whenNotPaused {
        require(whitelistTokens[token], "Controller: token is not whitelisted");
        require(amount > 0, "Controller: amount should be greater than zero");
        require(bytes(operator).length == 44, "Controller: invalid bech32 address");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        registeredRequests[outboundNonce + 1] = abi.encode(token, operator, msg.sender, amount);
        registeredRequestActions[outboundNonce + 1] = Action.REQUEST_UNDELEGATE_FROM;

        bytes memory actionArgs =
            abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), bytes(operator), amount);
        _sendInterchainMsg(Action.REQUEST_UNDELEGATE_FROM, actionArgs);
    }

    function _sendInterchainMsg(Action act, bytes memory actionArgs) internal {
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
