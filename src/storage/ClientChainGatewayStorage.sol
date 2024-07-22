pragma solidity ^0.8.19;

import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {BootstrapStorage} from "../storage/BootstrapStorage.sol";

import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";

contract ClientChainGatewayStorage is BootstrapStorage {

    /* -------------------------------------------------------------------------- */
    /*       state variables exclusively owned by ClientChainGateway              */
    /* -------------------------------------------------------------------------- */

    uint64 public outboundNonce; // the only contract that has outgoing messages
    mapping(address => IExoCapsule) public ownerToCapsule;
    mapping(uint64 => bytes) internal _registeredRequests;
    mapping(uint64 => Action) internal _registeredRequestActions;

    // immutable state variables
    address public immutable BEACON_ORACLE_ADDRESS;
    IBeacon public immutable EXO_CAPSULE_BEACON;

    // constant state variables
    uint256 internal constant TOKEN_ADDRESS_BYTES_LENGTH = 32;
    address internal constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    IETHPOSDeposit internal constant ETH_POS = IETHPOSDeposit(0x00000000219ab540356cBB839Cbe05303d7705Fa);
    // constants used for layerzero messaging
    uint128 internal constant DESTINATION_GAS_LIMIT = 500_000;
    uint128 internal constant DESTINATION_MSG_VALUE = 0;

    uint256[40] private __gap;

    /* -------------------------------------------------------------------------- */
    /*     ClientChainGateway Events(besides inherited from BootstrapStorage)     */
    /* -------------------------------------------------------------------------- */

    /* ---------------------------- native restaking ---------------------------- */
    event CapsuleCreated(address owner, address capsule);
    event StakedWithCapsule(address staker, address capsule);

    /* ----------------------------- restaking      ----------------------------- */
    event ClaimSucceeded(address token, address recipient, uint256 amount);
    event RequestFinished(Action indexed action, uint64 indexed requestId, bool indexed success);

    /* -------------------------------------------------------------------------- */
    /*                                   Errors                                   */
    /* -------------------------------------------------------------------------- */

    error CapsuleNotExist();

    constructor(
        uint32 exocoreChainId_,
        address beaconOracleAddress_,
        address vaultBeacon_,
        address exoCapsuleBeacon_,
        address beaconProxyBytecode_
    ) BootstrapStorage(exocoreChainId_, vaultBeacon_, beaconProxyBytecode_) {
        require(
            beaconOracleAddress_ != address(0),
            "ClientChainGatewayStorage: beacon chain oracle address should not be empty"
        );
        require(
            exoCapsuleBeacon_ != address(0),
            "ClientChainGatewayStorage: the exoCapsuleBeacon address for beacon proxy should not be empty"
        );

        BEACON_ORACLE_ADDRESS = beaconOracleAddress_;
        EXO_CAPSULE_BEACON = IBeacon(exoCapsuleBeacon_);
    }

    function _getCapsule(address owner) internal view returns (IExoCapsule) {
        IExoCapsule capsule = ownerToCapsule[owner];
        if (address(capsule) == address(0)) {
            revert CapsuleNotExist();
        }
        return capsule;
    }

}
