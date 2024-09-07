// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IClientChainGateway} from "../interfaces/IClientChainGateway.sol";
import {ITokenWhitelister} from "../interfaces/ITokenWhitelister.sol";
import {IVault} from "../interfaces/IVault.sol";

import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";
import {OAppReceiverUpgradeable} from "../lzApp/OAppReceiverUpgradeable.sol";
import {MessagingFee, OAppSenderUpgradeable} from "../lzApp/OAppSenderUpgradeable.sol";

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {ClientGatewayLzReceiver} from "./ClientGatewayLzReceiver.sol";
import {LSTRestakingController} from "./LSTRestakingController.sol";
import {NativeRestakingController} from "./NativeRestakingController.sol";

import {Errors} from "../libraries/Errors.sol";
import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

/// @title ClientChainGateway
/// @author ExocoreNetwork
/// @notice The gateway contract deployed on client chains for Exocore operations.
contract ClientChainGateway is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    IClientChainGateway,
    ITokenWhitelister,
    LSTRestakingController,
    NativeRestakingController,
    ClientGatewayLzReceiver
{

    using OptionsBuilder for bytes;

    /// @notice This constructor initializes only immutable state variables
    /// @param endpoint_ is the layerzero endpoint address deployed on this chain
    /// @param exocoreChainId_ is the id of layerzero endpoint on Exocore chain
    /// @param beaconOracleAddress_ is the Ethereum beacon chain oracle that is used for fetching beacon block root
    /// @param exoCapsuleBeacon_ is the UpgradeableBeacon contract address for ExoCapsule beacon proxy
    /// @param vaultBeacon_ is the UpgradeableBeacon contract address for Vault beacon proxy
    constructor(
        address endpoint_,
        uint32 exocoreChainId_,
        address beaconOracleAddress_,
        address vaultBeacon_,
        address exoCapsuleBeacon_,
        address beaconProxyBytecode_
    )
        OAppCoreUpgradeable(endpoint_)
        ClientChainGatewayStorage(
            exocoreChainId_,
            beaconOracleAddress_,
            vaultBeacon_,
            exoCapsuleBeacon_,
            beaconProxyBytecode_
        )
    {
        _disableInitializers();
    }

    /// @notice Initializes the ClientChainGateway contract.
    /// @dev reinitializer(2) is used so that the base contract (like OAppCore) functions can be called again.
    /// @param owner_ The address of the contract owner.
    function initialize(address owner_) external reinitializer(2) {
        _clearBootstrapData();

        if (owner_ == address(0)) {
            revert Errors.ZeroAddress();
        }

        _whiteListFunctionSelectors[Action.REQUEST_ADD_WHITELIST_TOKEN] =
            this.afterReceiveAddWhitelistTokenRequest.selector;
        _whiteListFunctionSelectors[Action.REQUEST_VALIDATE_LIMITS] = this.afterReceiveValidateLimitsRequest.selector;
        // overwrite the bootstrap function selector
        _whiteListFunctionSelectors[Action.REQUEST_MARK_BOOTSTRAP] = this.afterReceiveMarkBootstrapRequest.selector;

        bootstrapped = true;

        _transferOwnership(owner_);
        __OAppCore_init_unchained(owner_);
        __Pausable_init_unchained();
        __ReentrancyGuard_init_unchained();
    }

    /// @dev Clears the bootstrap data.
    function _clearBootstrapData() internal {
        // the set below is recommended to clear, so that any possibilities of upgrades
        // can then be removed.
        delete customProxyAdmin;
        delete clientChainGatewayLogic;
        delete clientChainInitializationData;
        // no risk keeping these but they are cheap to clear.
        delete spawnTime;
        delete offsetDuration;
        // previously, we tried clearing the contents of these in loops but it is too expensive.
        delete depositors;
        delete registeredValidators;
        // mappings cannot be deleted
    }

    /// @notice Pauses the contract.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @inheritdoc ITokenWhitelister
    function getWhitelistedTokensCount() external view returns (uint256) {
        return _getWhitelistedTokensCount();
    }

    /// @inheritdoc ITokenWhitelister
    function addWhitelistTokens(address[] calldata, uint256[] calldata) external view onlyOwner whenNotPaused {
        revert Errors.ClientChainGatewayTokenAdditionViaExocore();
    }

    /// @inheritdoc ITokenWhitelister
    function updateTvlLimit(address token, uint256 tvlLimit) external payable onlyOwner whenNotPaused {
        if (!isWhitelistedToken[token]) {
            // grave error, should never happen
            revert Errors.TokenNotWhitelisted(token);
        }
        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            // not possible to set a TVL limit for native restaking
            revert Errors.NoTvlLimitForNativeRestaking();
        }
        IVault vault = _getVault(token);
        uint256 previousLimit = vault.getTvlLimit();
        if (tvlLimit <= previousLimit) {
            // reduction of TVL limit is always allowed.
            if (msg.value > 0) {
                revert Errors.NonZeroValue();
            }
            vault.setTvlLimit(tvlLimit);
        } else {
            // queue message to Exocore for validation that the tvlLimit <= totalSupply.
            // to remove a configured tvl limit, set it (close to) the total supply (as on Exocore).
            // note that, since each message has an increasing nonce, multiple tvl updates may be in flight at once.
            // they will be processed in order.
            bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), tvlLimit);
            bytes memory encodedRequest = abi.encode(token, tvlLimit);
            _processRequest(Action.REQUEST_VALIDATE_LIMITS, actionArgs, encodedRequest);
            tvlLimitIncreasesInFlight[token]++;
        }
    }

    /// @inheritdoc IClientChainGateway
    function quote(bytes calldata _message) public view returns (uint256 nativeFee) {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(EXOCORE_CHAIN_ID, _message, options, false);
        return fee.nativeFee;
    }

    /// @inheritdoc IOAppCore
    function oAppVersion()
        public
        pure
        virtual
        override(IOAppCore, OAppSenderUpgradeable, OAppReceiverUpgradeable)
        returns (uint64 senderVersion, uint64 receiverVersion)
    {
        return (SENDER_VERSION, RECEIVER_VERSION);
    }

    /// @notice Called after a validate-limits request is received.
    /// @dev It checks that the proposed total supply >= tvlLimit.
    function afterReceiveValidateLimitsRequest(uint64 lzNonce, bytes calldata requestPayload)
        public
        onlyCalledFromThis
        whenNotPaused
    {
        (address token, uint256 newSupply) = _decodeTokenUint256(requestPayload, false);
        IVault vault = _getVault(token);
        uint256 tvlLimit = vault.getTvlLimit();
        bool success = tvlLimit <= newSupply && tvlLimitIncreasesInFlight[token] == 0;
        _sendMsgToExocore(Action.RESPOND, abi.encodePacked(lzNonce, success));
    }

}
