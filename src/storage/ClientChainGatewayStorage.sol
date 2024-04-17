pragma solidity ^0.8.19;

import {BootstrapStorage} from "./BootstrapStorage.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {GatewayStorage} from "./GatewayStorage.sol";

contract ClientChainGatewayStorage is BootstrapStorage {
    mapping(uint64 => bytes) public registeredRequests;
    mapping(uint64 => Action) public registeredRequestActions;
    mapping(Action => bytes4) public registeredResponseHooks;

    uint64 outboundNonce;

    uint128 constant DESTINATION_GAS_LIMIT = 500000;
    uint128 constant DESTINATION_MSG_VALUE = 0;

    // native restaking state variables
    mapping(address => IExoCapsule) public ownerToCapsule;
    mapping(IExoCapsule => bool) public isExoCapsule;
    address constant ETH_STAKING_DEPOSIT_CONTRACT_ADDRESS = 0x00000000219ab540356cBB839Cbe05303d7705Fa;
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

    // native restaking events
    event CapsuleCreated(address owner, address capsule);

    error UnauthorizedSigner();
    error UnauthorizedToken();
    error UnsupportedRequest(Action act);
    error UnsupportedResponse(Action act);
    error UnexpectedResponse(uint64 nonce);

    // native restaking errors
    error CapsuleNotExistForOwner(address owner);

    uint256[40] private __gap;
}
