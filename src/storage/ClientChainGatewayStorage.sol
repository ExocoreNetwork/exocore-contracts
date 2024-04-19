pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {GatewayStorage} from "./GatewayStorage.sol";

contract ClientChainGatewayStorage is GatewayStorage {
    uint256 lastMessageNonce;
    mapping(address => bool) public whitelistTokens;
    mapping(address => IVault) public tokenVaults;
    mapping(uint64 => bytes) public registeredRequests;
    mapping(uint64 => Action) public registeredRequestActions;
    mapping(Action => bytes4) public registeredResponseHooks;
    uint32 public exocoreChainId;

    uint64 outboundNonce;
    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) inboundNonce;

    uint128 constant DESTINATION_GAS_LIMIT = 500000;
    uint128 constant DESTINATION_MSG_VALUE = 0;

    // native restaking state variables
    mapping(address => IExoCapsule) public ownerToCapsule;
    IETHPOSDeposit constant ETH_POS = IETHPOSDeposit(0x00000000219ab540356cBB839Cbe05303d7705Fa);
    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 constant GWEI_TO_WEI = 1e9;

    event WhitelistTokenAdded(address _token);
    event WhitelistTokenRemoved(address _token);
    event VaultAdded(address _vault);
    event MessageProcessed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event MessageFailed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload, bytes _reason);
    event MessageSent(Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawPrincipleResult(
        bool indexed success, address indexed token, address indexed withdrawer, uint256 amount
    );
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event DelegateResult(
        bool indexed success, address indexed delegator, string delegatee, address token, uint256 amount
    );
    event UndelegateResult(
        bool indexed success, address indexed undelegator, string indexed undelegatee, address token, uint256 amount
    );
    event ClaimSucceeded(address token, address recipient, uint256 amount);

    // native restaking events
    event CapsuleCreated(address owner, address capsule);
    event StakedWithCapsule(address staker, address capsule);

    error UnauthorizedSigner();
    error UnauthorizedToken();
    error UnsupportedRequest(Action act);
    error UnsupportedResponse(Action act);
    error RequestOrResponseExecuteFailed(Action act, uint64 nonce, bytes reason);
    error VaultNotExist();
    error ActionFailed(Action act, uint64 nonce);
    error UnexpectedResponse(uint64 nonce);
    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);
    error UnexpectedSourceChain(uint32 unexpectedSrcEndpointId);
    error DepositShouldNotFailOnExocore(address token, address depositor);

    // native restaking errors
    error CapsuleNotExist();

    uint256[40] private __gap;

    function _getVault(address token) internal view returns (IVault) {
        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }
        return vault;
    }

    function _getCapsule(address owner) internal view returns (IExoCapsule) {
        IExoCapsule capsule = ownerToCapsule[owner];
        if (address(capsule) == address(0)) {
            revert CapsuleNotExist();
        }
        return capsule;
    }
}
