pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";
import {OAppSenderUpgradeable, MessagingFee} from "../lzApp/OAppSenderUpgradeable.sol";
import {OAppReceiverUpgradeable} from "../lzApp/OAppReceiverUpgradeable.sol";
import {LSTRestakingController} from "./LSTRestakingController.sol";
import {NativeRestakingController} from "./NativeRestakingController.sol";
import {ClientGatewayLzReceiver} from "./ClientGatewayLzReceiver.sol";
import {IClientChainGateway} from "../interfaces/IClientChainGateway.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {Vault} from "./Vault.sol";

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

contract ClientChainGateway is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    IClientChainGateway,
    LSTRestakingController,
    NativeRestakingController,
    ClientGatewayLzReceiver
{
    using OptionsBuilder for bytes;

    /**
     * @notice This constructor initializes only immutable state variables
     * @param endpoint_ is the layerzero endpoint address deployed on this chain
     * @param exocoreChainId_ is the id of layerzero endpoint on Exocore chain
     * @param beaconOracleAddress_ is the Ethereum beacon chain oracle that is used for fetching beacon block root
     * @param exoCapsuleBeacon_ is the UpgradeableBeacon contract address for ExoCapsule beacon proxy
     * @param vaultBeacon_ is the UpgradeableBeacon contract address for Vault beacon proxy
     */
    constructor(
        address endpoint_, 
        uint32 exocoreChainId_, 
        address beaconOracleAddress_,
        address vaultBeacon_,
        address exoCapsuleBeacon_
    ) 
        OAppCoreUpgradeable(endpoint_)
        ClientChainGatewayStorage(exocoreChainId_, beaconOracleAddress_, vaultBeacon_, exoCapsuleBeacon_) 
    {
        _disableInitializers();
    }

    // initialization happens from another contract so it must be external.
    // reinitializer(2) is used so that the ownable and oappcore functions can be called again.
    function initialize(
        address payable exocoreValidatorSetAddress_,
        address[] calldata appendedWhitelistTokens_
    ) external reinitializer(2) {
        clearBootstrapData();
        
        require(exocoreValidatorSetAddress_ != address(0), "ClientChainGateway: exocore validator set address should not be empty");

        exocoreValidatorSetAddress = exocoreValidatorSetAddress_;

        for (uint256 i = 0; i < appendedWhitelistTokens_.length; i++) {
            address underlyingToken = appendedWhitelistTokens_[i];
            require(!isWhitelistedToken[underlyingToken], "ClientChainGateway: token should not be whitelisted before");

            whitelistTokens.push(underlyingToken);
            isWhitelistedToken[underlyingToken] = true;
            emit WhitelistTokenAdded(underlyingToken);

            // deploy the corresponding vault if not deployed before
            if (address(tokenToVault[underlyingToken]) == address(0)) {
                _deployVault(underlyingToken);
            }
        }

        _registeredResponseHooks[Action.REQUEST_DEPOSIT] = this.afterReceiveDepositResponse.selector;
        _registeredResponseHooks[Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE] =
            this.afterReceiveWithdrawPrincipleResponse.selector;
        _registeredResponseHooks[Action.REQUEST_DELEGATE_TO] = this.afterReceiveDelegateResponse.selector;
        _registeredResponseHooks[Action.REQUEST_UNDELEGATE_FROM] = this.afterReceiveUndelegateResponse.selector;
        _registeredResponseHooks[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] =
            this.afterReceiveWithdrawRewardResponse.selector;

        bootstrapped = true;

        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __OAppCore_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    function clearBootstrapData() internal {
        // mandatory to clear!
        delete _whiteListFunctionSelectors[Action.MARK_BOOTSTRAP];
        // the set below is recommended to clear, so that any possibilities of upgrades
        // can then be removed.
        delete customProxyAdmin;
        delete clientChainGatewayLogic;
        delete clientChainInitializationData;
        // no risk keeping these but they are cheap to clear.
        delete exocoreSpawnTime;
        delete offsetDuration;
        // TODO: are these loops even worth it? the maximum refund is 50% of the gas cost.
        // if not, we can remove them.
        // the lines above this set of comments are at least cheaper to clear,
        // and have no utility after initialization.
        for(uint i = 0; i < depositors.length; i++) {
            address depositor = depositors[i];
            for(uint j = 0; j < whitelistTokens.length; j++) {
                address token = whitelistTokens[j];
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
            for(uint j = 0; j < whitelistTokens.length; j++) {
                address token = whitelistTokens[j];
                delete delegationsByOperator[exo][token];
            }
        }
        for(uint j = 0; j < whitelistTokens.length; j++) {
            address token = whitelistTokens[j];
            delete depositsByToken[token];
        }
        // these should also be cleared - even if the loops are not used
        // cheap to clear and potentially large in size.
        delete depositors;
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

    function addWhitelistToken(address _token) public onlyOwner whenNotPaused {
        require(!isWhitelistedToken[_token], "ClientChainGateway: token should not be whitelisted before");
        whitelistTokens.push(_token);
        isWhitelistedToken[_token] = true;
        emit WhitelistTokenAdded(_token);

        // deploy the corresponding vault if not deployed before
        if (address(tokenToVault[_token]) == address(0)) {
            _deployVault(_token);
        }
    }

    function removeWhitelistToken(address _token) external onlyOwner whenNotPaused {
        require(isWhitelistedToken[_token], "ClientChainGateway: token should be already whitelisted");
        isWhitelistedToken[_token] = false;
        for(uint i = 0; i < whitelistTokens.length; i++) {
            if (whitelistTokens[i] == _token) {
                whitelistTokens[i] = whitelistTokens[whitelistTokens.length - 1];
                whitelistTokens.pop();
                break;
            }
        }

        emit WhitelistTokenRemoved(_token);
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

    function _deployVault(address underlyingToken) internal returns (IVault) {
        Vault vault = Vault(
            Create2.deploy(
                0,
                bytes32(uint256(uint160(underlyingToken))),
                // set the beacon address for beacon proxy
                abi.encodePacked(BEACON_PROXY_BYTECODE, abi.encode(address(vaultBeacon), ""))
            )
        );
        vault.initialize(underlyingToken, address(this));
        emit VaultCreated(underlyingToken, address(vault));

        tokenToVault[underlyingToken] = vault;
    }
}
