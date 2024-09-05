// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IClientChainGateway} from "../interfaces/IClientChainGateway.sol";
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

    /// @notice Gets the count of whitelisted tokens.
    /// @return The count of whitelisted tokens.
    function getWhitelistedTokensCount() external view returns (uint256) {
        return whitelistTokens.length;
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

}
