pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {ITSSReceiver} from "../interfaces/ITSSReceiver.sol";
import {IController} from "../interfaces/IController.sol";
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
import {Controller} from "./Controller.sol";
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
    Controller,
    ClientChainLzReceiver,
    TSSReceiver
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    using OptionsBuilder for bytes;

    constructor(address _endpoint) OAppCoreUpgradeable(_endpoint) {
        _disableInitializers();
    }

    // initialization happens from another contract so it must be external.
    // reinitializer(2) is used so that the ownable and oappcore functions can be called again.
    function initialize(
        uint32 _exocoreChainId,
        address payable _exocoreValidatorSetAddress,
        address[] calldata _whitelistTokens
    ) external reinitializer(2) {
        clearBootstrapData();
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

        bootstrapped = true;

        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __OAppCore_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    function clearBootstrapData() internal {
        // mandatory to clear!
        delete whiteListFunctionSelectors[Action.MARK_BOOTSTRAP];
        // the set below is recommended to clear, so that any possibilities of upgrades
        // can then be removed.
        delete customProxyAdmin;
        delete clientChainGatewayLogic;
        delete clientChainInitializationData;
        // no risk keeping these but they are cheap to clear.
        delete exocoreSpawnTime;
        delete offsetTime;
        // TODO: are these loops even worth it? the maximum refund is 50% of the gas cost.
        // if not, we can remove them.
        // the lines above this set of comments are at least cheaper to clear,
        // and have no utility after initialization.
        for(uint i = 0; i < depositors.length; i++) {
            address depositor = depositors[i];
            for(uint j = 0; j < whitelistTokensArray.length; j++) {
                address token = whitelistTokensArray[j];
                delete totalDepositAmounts[depositor][token];
                delete withdrawableAmounts[depositor][token];
                for(uint k = 0; k < registeredOperators.length; k++) {
                    address eth = registeredOperators[k];
                    string memory exo = ethToExocoreAddress[eth];
                    delete delegations[depositor][exo][token];
                }
            }
            delete isDepositor[depositor];
        }
        for(uint k = 0; k < registeredOperators.length; k++) {
            address eth = registeredOperators[k];
            string memory exo = ethToExocoreAddress[eth];
            delete operators[exo];
            delete commissionEdited[exo];
            delete ethToExocoreAddress[eth];
            for(uint j = 0; j < whitelistTokensArray.length; j++) {
                address token = whitelistTokensArray[j];
                delete delegationsByOperator[exo][token];
            }
        }
        for(uint j = 0; j < whitelistTokensArray.length; j++) {
            address token = whitelistTokensArray[j];
            delete depositsByToken[token];
        }
        delete depositors;
        delete whitelistTokensArray;
        delete registeredOperators;
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
            if (address(tokenVaults[underlyingToken]) != address(0)) {
                revert VaultAlreadyAdded();
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

    function afterReceiveDepositResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address depositor, uint256 amount) = abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipleBalance = uint256(bytes32(responsePayload[1:]));
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

            vault.updatePrincipleBalance(depositor, lastlyUpdatedPrincipleBalance);
        }

        emit DepositResult(success, token, depositor, amount);
    }

    function afterReceiveWithdrawPrincipleResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address withdrawer, uint256 unlockPrincipleAmount) =
            abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipleBalance = uint256(bytes32(responsePayload[1:33]));
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

            vault.updatePrincipleBalance(withdrawer, lastlyUpdatedPrincipleBalance);
            vault.updateWithdrawableBalance(withdrawer, unlockPrincipleAmount, 0);
        }

        emit WithdrawPrincipleResult(success, token, withdrawer, unlockPrincipleAmount);
    }

    function afterReceiveWithdrawRewardResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address withdrawer, uint256 unlockRewardAmount) =
            abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedRewardBalance = uint256(bytes32(responsePayload[1:33]));
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

            vault.updateRewardBalance(withdrawer, lastlyUpdatedRewardBalance);
            vault.updateWithdrawableBalance(withdrawer, 0, unlockRewardAmount);
        }

        emit WithdrawRewardResult(success, token, withdrawer, unlockRewardAmount);
    }

    function afterReceiveDelegateResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, string memory operator, address delegator, uint256 amount) =
            abi.decode(requestPayload, (address, string, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit DelegateResult(success, delegator, operator, token, amount);
    }

    function afterReceiveUndelegateResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, string memory operator, address undelegator, uint256 amount) =
            abi.decode(requestPayload, (address, string, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit UndelegateResult(success, undelegator, operator, token, amount);
    }
}
