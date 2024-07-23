// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";

/// @title ExocoreGatewayStorage
/// @notice Storage used by the ExocoreGateway contract.
/// @author ExocoreNetwork
contract ExocoreGatewayStorage is GatewayStorage {

    /// @dev The length of a deposit request, in bytes.
    // bytes32 token + bytes32 depositor + uint256 amount
    uint256 internal constant DEPOSIT_REQUEST_LENGTH = 96;

    /// @dev The length of a delegate request, in bytes.
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DELEGATE_REQUEST_LENGTH = 138;

    /// @dev The length of an undelegate request, in bytes.
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant UNDELEGATE_REQUEST_LENGTH = 138;

    /// @dev The length of a withdraw principal request, in bytes.
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant WITHDRAW_PRINCIPAL_REQUEST_LENGTH = 96;

    /// @dev The length of a claim reward request, in bytes.
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant CLAIM_REWARD_REQUEST_LENGTH = 96;

    /// @dev The length of a deposit-then-delegate request, in bytes.
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH = DELEGATE_REQUEST_LENGTH;
    // bytes32 staker + bytes(42) operator
    uint256 internal constant ASSOCIATE_OPERATOR_REQUEST_LENGTH = 74;
    // bytes32 staker
    uint256 internal constant DISSOCIATE_OPERATOR_REQUEST_LENGTH = 32;

    // constants used for layerzero messaging
    /// @dev The gas limit for all the destination chains.
    uint128 internal constant DESTINATION_GAS_LIMIT = 500_000;

    /// @dev The msg.value for all the destination chains.
    uint128 internal constant DESTINATION_MSG_VALUE = 0;

    /// @notice A mapping from client chain IDs to whether the chain has been bootstrapped.
    /// @dev Used to ensure no repeated bootstrap requests are sent.
    mapping(uint32 clienChainId => bool) public chainToBootstrapped;

    /// @notice A mapping from client chain IDs to whether the chain has been registered.
    /// @dev Used to ensure that only registered client chains can interact with the gateway.
    mapping(uint32 clienChainId => bool registered) public isRegisteredClientChain;

    /// @notice A mapping from token address to whether the token is whitelisted.
    /// @dev Used to ensure no duplicate tokens are added to the whitelist.
    mapping(bytes32 token => bool whitelisted) public isWhitelistedToken;

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
    event WithdrawRewardResult(bool indexed success, bytes32 indexed token, bytes32 indexed withdrawer, uint256 amount);

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
    event WithdrawPrincipalResult(
        bool indexed success, bytes32 indexed token, bytes32 indexed withdrawer, uint256 amount
    );

    /// @notice Emitted upon delegation.
    /// @param success Whether the delegation was successful.
    /// @param token The address of the token.
    /// @param delegator The address of the delegator.
    /// @param operator The Exo account address of the operator.
    /// @param amount The amount of the token delegated.
    event DelegateResult(
        bool indexed success, bytes32 indexed token, bytes32 indexed delegator, string operator, uint256 amount
    );

    /// @notice Emitted upon undelegation
    /// @param success Whether the undelegation was successful.
    /// @param token The address of the token.
    /// @param undelegator The address of the undelegator.
    /// @param operator The Exo account address of the operator.
    /// @param amount The amount of the token undelegated.
    event UndelegateResult(
        bool indexed success, bytes32 indexed token, bytes32 indexed undelegator, string operator, uint256 amount
    );
    event AssociateOperatorResult(bool indexed success, bytes32 indexed staker, bytes32 indexed operator);
    event DissociateOperatorResult(bool indexed success, bytes32 indexed staker);

    /// @notice Thrown when the execution of a request fails
    /// @param act The action that failed.
    /// @param nonce The LayerZero nonce.
    /// @param reason The reason for the failure.
    error RequestExecuteFailed(Action act, uint64 nonce, bytes reason);

    /// @notice Thrown when the execution of a precompile call fails.
    /// @param selector_ The function selector of the precompile call.
    /// @param reason The reason for the failure.
    error PrecompileCallFailed(bytes4 selector_, bytes reason);

    /// @notice Thrown when the request length is invalid.
    /// @param act The action that failed.
    /// @param expectedLength The expected length of the request.
    /// @param actualLength The actual length of the request.
    error InvalidRequestLength(Action act, uint256 expectedLength, uint256 actualLength);

    /// @notice Thrown when a deposit request fails.
    /// @param srcChainId The source chain ID.
    /// @param lzNonce The LayerZero nonce.
    /// @dev This is considered a critical error.
    error DepositRequestShouldNotFail(uint32 srcChainId, uint64 lzNonce);

    /// @notice Thrown when a client chain registration fails
    /// @param clientChainId The LayerZero chain ID of the client chain.
    error RegisterClientChainToExocoreFailed(uint32 clientChainId);

    /// @notice Thrown when a whitelist token addition fails
    /// @param token The address of the token.
    error AddWhitelistTokenFailed(bytes32 token);

    /// @notice Thrown when a whitelist token update fails
    /// @param token The address of the token.
    error UpdateWhitelistTokenFailed(bytes32 token);

    /// @notice Thrown when the whitelist tokens input is invalid.
    error InvalidWhitelistTokensInput();

    /// @notice Thrown when the client chain ID is not registered.
    /// @param clientChainId The LayerZero chain ID of the client chain.
    error ClientChainIDNotRegisteredBefore(uint32 clientChainId);

    /// @notice Thrown when the whitelist tokens list is too long.
    error WhitelistTokensListTooLong();
    error AssociateOperatorFailed(uint32 clientChainId, string staker, string operator);
    error DissociateOperatorFailed(uint32 clientChainId, string staker);

    /// @dev Storage gap to allow for future upgrades.
    uint256[40] private __gap;

}
