pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";
import {GatewayStorage} from "./GatewayStorage.sol";

contract ClientChainGatewayStorage is GatewayStorage {
    uint256 lastMessageNonce;
    mapping(address => bool) public whitelistTokens;
    mapping(address => IVault) public tokenVaults;
    mapping(uint64 => bytes) public registeredRequests;
    mapping(uint64 => Action) public registeredRequestActions;
    mapping(Action => bytes4) public registeredResponseHooks;
    uint32 public exocoreChainID;
    uint64 outboundNonce;

    uint256[40] private __gap;

    event WhitelistTokenAdded(address _token);
    event WhitelistTokenRemoved(address _token);
    event VaultAdded(address _vault);
    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event MessageFailed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload, bytes _reason);
    event RequestSent(Action indexed act);
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawPrincipleResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event DelegateResult(bool indexed success, address indexed delegator, string delegatee, address token, uint256 amount);
    event UndelegateResult(bool indexed success, address indexed undelegator, string indexed undelegatee, address token, uint256 amount);

    error UnauthorizedSigner();
    error UnauthorizedToken();
    error UnsupportedRequest(Action act);
    error UnsupportedResponse(Action act); 
    error RequestOrResponseExecuteFailed(Action act, uint64 nonce, bytes reason);
    error VaultNotExist();
    error ActionFailed(Action act, uint64 nonce);
    error UnexpectedResponse(uint64 nonce);
}