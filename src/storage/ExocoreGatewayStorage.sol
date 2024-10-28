// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ActionAttributes} from "../libraries/ActionAttributes.sol";
import {Errors} from "../libraries/Errors.sol";
import {Action, GatewayStorage} from "./GatewayStorage.sol";

/// @title ExocoreGatewayStorage
/// @notice Storage used by the ExocoreGateway contract.
/// @author ExocoreNetwork
contract ExocoreGatewayStorage is GatewayStorage {

    using ActionAttributes for Action;

    // constants used for layerzero messaging
    /// @dev The gas limit for all the destination chains.
    uint128 internal constant DESTINATION_GAS_LIMIT = 500_000;

    /// @dev The msg.value for all the destination chains.
    uint128 internal constant DESTINATION_MSG_VALUE = 0;

    /// constants used for solana mainnet chainId
    /// @dev the solana mainnet chain id
    uint32 internal constant SOLANA_MAINNET_CHAIN_ID = 30_168;

    /// constants used for solana devnet chainId
    /// @dev the solana devnet chain id
    uint32 internal constant SOLANA_DEVNET_CHAIN_ID = 40_168;

    /// @dev the msg.value for send addTokenWhiteList message
    uint128 internal constant SOLANA_MSG_VALUE = 3_000_000;

    /// @notice Emitted when a precompile call fails.
    /// @param precompile Address of the precompile contract.
    /// @param nonce The LayerZero nonce
    event ExocorePrecompileError(address indexed precompile, uint64 nonce);

    /// @notice Emitted upon the registration of a new client chain.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    event ClientChainRegistered(uint32 clientChainId);

    /// @notice Emitted upon the update of a client chain.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    event ClientChainUpdated(uint32 clientChainId);

    /// @notice Emitted when a token is added to the whitelist.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    /// @param token The address of the token.
    event WhitelistTokenAdded(uint32 clientChainId, bytes32 token);

    /// @notice Emitted when a token is updated in the whitelist.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    /// @param token The address of the token.
    event WhitelistTokenUpdated(uint32 clientChainId, bytes32 token);

    /* --------- asset operations results and staking operations results -------- */

    /// @notice Emitted when a reward operation is executed, submit or claim.
    /// @param isSubmitReward Whether the operation is a submit reward or a claim reward.
    /// @param success Whether the operation was successful.
    /// @param token The address of the token.
    /// @param avsOrWithdrawer The address of the avs or withdrawer, avs for submit reward, withdrawer for claim reward.
    /// @param amount The amount of the token submitted or claimed.
    event RewardOperation(
        bool isSubmitReward,
        bool indexed success,
        bytes32 indexed token,
        bytes32 indexed avsOrWithdrawer,
        uint256 amount
    );

    /// @notice Emitted when a LST transfer happens.
    /// @param isDeposit Whether the transfer is a deposit or a withdraw.
    /// @param success Whether the transfer was successful.
    /// @param token The address of the token.
    /// @param staker The address that makes the transfer.
    /// @param amount The amount of the token transferred.
    event LSTTransfer(
        bool isDeposit, bool indexed success, bytes32 indexed token, bytes32 indexed staker, uint256 amount
    );

    /// @notice Emitted when a NST transfer happens.
    /// @param isDeposit Whether the transfer is a deposit or a withdraw.
    /// @param success Whether the transfer was successful.
    /// @param validatorPubkey The validator public key.
    /// @param staker The address that makes the transfer.
    /// @param amount The amount of the token transferred.
    event NSTTransfer(
        bool isDeposit, bool indexed success, bytes32 indexed validatorPubkey, bytes32 indexed staker, uint256 amount
    );

    /// @notice Emitted upon receiving a delegation request.
    /// @param isDelegate Whether the delegation request is a delegate request or an undelegate request.
    /// @param accepted Whether the delegation request was accepted, true if it is accepted and being queued, false if
    /// rejected.
    /// @param token The address of the token.
    /// @param delegator The address of the delegator.
    /// @param operator The Exo account address of the operator.
    /// @param amount The amount of the token delegated/undelegated.
    event DelegationRequest(
        bool isDelegate,
        bool indexed accepted,
        bytes32 indexed token,
        bytes32 indexed delegator,
        string operator,
        uint256 amount
    );

    /// @notice Emitted upon handling associating operator request
    /// @param success Whether the operation was successful.
    /// @param isAssociate Whether the operation is an association or a dissociation.
    /// @param staker The staker address involved in the association or dissociation.
    event AssociationResult(bool indexed success, bool indexed isAssociate, bytes32 indexed staker);

    /// @notice Emitted when a REQUEST_MARK_BOOTSTRAP is sent to @param clientChainId.
    /// @param clientChainId The LayerZero chain ID of chain to which it is destined.
    event BootstrapRequestSent(uint32 clientChainId);

    /// @dev Storage gap to allow for future upgrades.
    uint256[40] private __gap;

    /**
     * @dev Validates the message length based on the action.
     * @param message The message to validate.
     */
    function _validateMessageLength(bytes calldata message) internal pure {
        if (message.length < 1) {
            revert Errors.InvalidMessageLength();
        }
        Action action = Action(uint8(message[0]));
        uint256 expectedLength = action.getMessageLength();

        if (expectedLength == 0) {
            revert Errors.UnsupportedRequest(action);
        }

        if (message.length != expectedLength) {
            revert Errors.InvalidMessageLength();
        }
    }

}
