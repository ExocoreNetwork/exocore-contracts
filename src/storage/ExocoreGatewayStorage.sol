pragma solidity ^0.8.19;

import {GatewayStorage} from "./GatewayStorage.sol";

contract ExocoreGatewayStorage is GatewayStorage {

    // bytes32 token + bytes32 depositor + uint256 amount
    uint256 internal constant DEPOSIT_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DELEGATE_REQUEST_LENGTH = 138;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant UNDELEGATE_REQUEST_LENGTH = 138;
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant WITHDRAW_PRINCIPAL_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 withdrawer + uint256 amount
    uint256 internal constant CLAIM_REWARD_REQUEST_LENGTH = 96;
    // bytes32 token + bytes32 delegator + bytes(42) operator + uint256 amount
    uint256 internal constant DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH = DELEGATE_REQUEST_LENGTH;
    uint256 internal constant TOKEN_ADDRESS_BYTES_LENTH = 32;
    uint256 internal constant UINT8_BYTES_LENGTH = 1;
    uint256 internal constant UINT256_BYTES_LENGTH = 32;

    uint128 internal constant DESTINATION_GAS_LIMIT = 500_000;
    uint128 internal constant DESTINATION_MSG_VALUE = 0;

    mapping(uint32 clienChainId => bool) public chainToBootstrapped;
    mapping(uint32 clienChainId => bool registered) public isRegisteredClientChain;
    mapping(bytes32 token => bool whitelisted) public isWhitelistedToken;

    event ExocorePrecompileError(address indexed precompile, uint64 nonce);
    event ClientChainRegistered(uint32 clientChainId);
    event ClientChainUpdated(uint32 clientChainId);
    event WhitelistTokenAdded(uint32 clientChainId, bytes32 token);
    event WhitelistTokenUpdated(uint32 clientChainId, bytes32 token);

    error RequestExecuteFailed(Action act, uint64 nonce, bytes reason);
    error PrecompileCallFailed(bytes4 selector_, bytes reason);
    error InvalidRequestLength(Action act, uint256 expectedLength, uint256 actualLength);
    error DepositRequestShouldNotFail(uint32 srcChainId, uint64 lzNonce);
    error RegisterClientChainToExocoreFailed(uint32 clientChainId);
    error AddWhitelistTokenFailed(bytes32 token);
    error UpdateWhitelistTokenFailed(bytes32 token);
    error InvalidWhitelistTokensInput();
    error ClientChainIDNotRegisteredBefore(uint32 clientChainId);
    error WhitelistTokensListTooLong();

    uint256[40] private __gap;

}
