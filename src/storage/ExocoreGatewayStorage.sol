// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Action, GatewayStorage} from "./GatewayStorage.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title ExocoreGatewayStorage
/// @notice Storage used by the ExocoreGateway contract.
/// @author ExocoreNetwork
contract ExocoreGatewayStorage is GatewayStorage {

    /// @dev The length of a deposit LST request, in bytes.
    // uint8 Action + bytes32 token + bytes32 depositor + uint256 amount
    uint256 internal constant DEPOSIT_LST_REQUEST_LENGTH = 97;

    /// @dev The length of a deposit NST request, in bytes.
    // uint8 Action + bytes32 validatorPubkey + bytes32 depositor + uint256 amount
    uint256 internal constant DEPOSIT_NST_REQUEST_LENGTH = 97;

    /// @dev The length of a delegate request, in bytes.
    // uint8 Action + bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DELEGATE_REQUEST_LENGTH = 139;

    /// @dev The length of an undelegate request, in bytes.
    // uint8 Action + bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant UNDELEGATE_REQUEST_LENGTH = 139;

    /// @dev The length of a withdraw LST request, in bytes.
    // uint8 Action + bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant WITHDRAW_LST_REQUEST_LENGTH = 97;

    /// @dev The length of a withdraw NST request, in bytes.
    // uint8 Action + bytes32 validatorPubkey + bytes32 withdrawer + uint256 amount
    uint256 internal constant WITHDRAW_NST_REQUEST_LENGTH = 97;

    /// @dev The length of a claim reward request, in bytes.
    // uint8 Action + bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant CLAIM_REWARD_REQUEST_LENGTH = 97;

    /// @dev The length of a deposit-then-delegate request, in bytes.
    // uint8 Action + bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH = DELEGATE_REQUEST_LENGTH;
    // uint8 Action + bytes32 staker + bytes(42) operator
    uint256 internal constant ASSOCIATE_OPERATOR_REQUEST_LENGTH = 75;
    // uint8 Action + bytes32 staker
    uint256 internal constant DISSOCIATE_OPERATOR_REQUEST_LENGTH = 33;

    // constants used for layerzero messaging
    /// @dev The gas limit for all the destination chains.
    uint128 internal constant DESTINATION_GAS_LIMIT = 500_000;

    /// @dev The msg.value for all the destination chains.
    uint128 internal constant DESTINATION_MSG_VALUE = 0;

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
    /// @notice Emitted when reward is withdrawn.
    /// @param success Whether the withdrawal was successful.
    /// @param token The address of the token.
    /// @param withdrawer The address of the withdrawer.
    /// @param amount The amount of the token withdrawn.
    event ClaimRewardResult(bool indexed success, bytes32 indexed token, bytes32 indexed withdrawer, uint256 amount);

    /// @notice Emitted when a deposit happens.
    /// @param success Whether the deposit was successful.
    /// @param token The address of the token.
    /// @param depositor The address of the depositor.
    /// @param amount The amount of the token deposited.
    event DepositResult(bool indexed success, bytes32 indexed token, bytes32 indexed depositor, uint256 amount);

    /// @notice Emitted when principal is withdrawn.
    /// @param success Whether the withdrawal was successful.
    /// @param token The address of the token.
    /// @param withdrawer The address of the withdrawer.
    /// @param amount The amount of the token withdrawn.
    event WithdrawalResult(
        bool indexed success, bytes32 indexed token, bytes32 indexed withdrawer, uint256 amount
    );

    /// @notice Emitted upon delegation.
    /// @param accepted Whether the delegation request was accepted, true if it is accepted and being queued, false if it is rejected.
    /// @param isDelegate Whether the delegation request is a delegate request or an undelegate request.
    /// @param token The address of the token.
    /// @param delegator The address of the delegator.
    /// @param operator The Exo account address of the operator.
    /// @param amount The amount of the token delegated.
    event DelegationRequestReceived(
        bool indexed accepted, bool indexed isDelegate, bytes32 indexed token, bytes32 delegator, string operator, uint256 amount
    );

    /// @notice Emitted upon handling associating operator request
    /// @param success Whether the operation was successful.
    /// @param isAssociate Whether the operation is an association or a dissociation.
    /// @param staker The staker address that should be associated to @operator.
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
        uint256 expectedLength;

        if (action == Action.REQUEST_DEPOSIT_LST) {
            expectedLength = DEPOSIT_LST_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_DEPOSIT_NST) {
            expectedLength = DEPOSIT_NST_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_WITHDRAW_LST) {
            expectedLength = WITHDRAW_LST_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_WITHDRAW_NST) {
            expectedLength = WITHDRAW_NST_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_CLAIM_REWARD) {
            expectedLength = CLAIM_REWARD_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_DELEGATE_TO) {
            expectedLength = DELEGATE_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_UNDELEGATE_FROM) {
            expectedLength = UNDELEGATE_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO) {
            expectedLength = DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_ASSOCIATE_OPERATOR) {
            expectedLength = ASSOCIATE_OPERATOR_REQUEST_LENGTH;
        } else if (action == Action.REQUEST_DISSOCIATE_OPERATOR) {
            expectedLength = DISSOCIATE_OPERATOR_REQUEST_LENGTH;
        } else {
            revert Errors.UnsupportedRequest(action);
        }

        if (message.length != expectedLength) {
            revert Errors.InvalidMessageLength();
        }
    }

}
