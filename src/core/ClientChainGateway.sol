pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {ITSSReceiver} from "../interfaces/ITSSReceiver.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";
import {OAppSenderUpgradeable, MessagingFee} from "../lzApp/OAppSenderUpgradeable.sol";
import {OAppReceiverUpgradeable} from "../lzApp/OAppReceiverUpgradeable.sol";
import {ECDSA} from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {LSTRestakingController} from "./LSTRestakingController.sol";
import {NativeRestakingController} from "./NativeRestakingController.sol";
import {ClientChainLzReceiver} from "./ClientChainLzReceiver.sol";
import {TSSReceiver} from "./TSSReceiver.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {IClientChainGateway} from "../interfaces/IClientChainGateway.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";

contract ClientChainGateway is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    IClientChainGateway,
    LSTRestakingController,
    NativeRestakingController,
    ClientChainLzReceiver,
    TSSReceiver
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    using OptionsBuilder for bytes;

    constructor(address _endpoint) OAppCoreUpgradeable(_endpoint) {
        _disableInitializers();
    }

    function initialize(
        uint32 _exocoreChainId,
        address payable _exocoreValidatorSetAddress,
        address[] calldata _whitelistTokens
    ) external initializer {
        require(_exocoreValidatorSetAddress != address(0), "ClientChainGateway: exocore validator set address should not be empty");
        require(_exocoreChainId != 0, "ClientChainGateway: exocore chain id should not be empty");

        exocoreValidatorSetAddress = _exocoreValidatorSetAddress;
        exocoreChainId = _exocoreChainId;

        for (uint256 i = 0; i < _whitelistTokens.length; i++) {
            whitelistTokens[_whitelistTokens[i]] = true;
        }

        whiteListFunctionSelectors[Action.UPDATE_USERS_BALANCES] = this.updateUsersBalances.selector;

        registeredResponseHooks[Action.REQUEST_DEPOSIT] = this.afterReceiveDepositResponse.selector;
        registeredResponseHooks[Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE] =
            this.afterReceiveWithdrawPrincipleResponse.selector;
        registeredResponseHooks[Action.REQUEST_DELEGATE_TO] = this.afterReceiveDelegateResponse.selector;
        registeredResponseHooks[Action.REQUEST_UNDELEGATE_FROM] = this.afterReceiveUndelegateResponse.selector;
        registeredResponseHooks[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] =
            this.afterReceiveWithdrawRewardResponse.selector;

        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __OAppCore_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    function pause() external {
        require(
            msg.sender == exocoreValidatorSetAddress, "ClientChainGateway: caller is not Exocore validator set aggregated address"
        );
        _pause();
    }

    function unpause() external {
        require(
            msg.sender == exocoreValidatorSetAddress, "ClientChainGateway: caller is not Exocore validator set aggregated address"
        );
        _unpause();
    }

    function addWhitelistToken(address _token) external onlyOwner whenNotPaused {
        require(!whitelistTokens[_token], "ClientChainGateway: token should be not whitelisted before");
        whitelistTokens[_token] = true;

        emit WhitelistTokenAdded(_token);
    }

    function removeWhitelistToken(address _token) external onlyOwner whenNotPaused {
        require(whitelistTokens[_token], "ClientChainGateway: token should be already whitelisted");
        whitelistTokens[_token] = false;

        emit WhitelistTokenRemoved(_token);
    }

    function addTokenVaults(address[] calldata vaults) external onlyOwner whenNotPaused {
        for (uint256 i = 0; i < vaults.length; i++) {
            address underlyingToken = IVault(vaults[i]).getUnderlyingToken();
            if (!whitelistTokens[underlyingToken]) {
                revert UnauthorizedToken();
            }
            tokenVaults[underlyingToken] = IVault(vaults[i]);

            emit VaultAdded(vaults[i]);
        }
    }

    function quote(bytes memory _message) public view returns (uint256 nativeFee) {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(exocoreChainId, _message, options, false);
        return fee.nativeFee;
    }

    /**
     * @notice Retrieves the OApp version information.
     * @return senderVersion The version of the OAppSender.sol implementation.
     * @return receiverVersion The version of the OAppReceiver.sol implementation.
     */
    function oAppVersion()
        public
        pure
        virtual
        override(IOAppCore, OAppSenderUpgradeable, OAppReceiverUpgradeable)
        returns (uint64 senderVersion, uint64 receiverVersion)
    {
        return (SENDER_VERSION, RECEIVER_VERSION);
    }
}
