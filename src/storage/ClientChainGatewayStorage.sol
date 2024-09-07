// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {BootstrapStorage} from "../storage/BootstrapStorage.sol";

import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";

/// @title ClientChainGatewayStorage
/// @author ExocoreNetwork
/// @notice ClientChainGatewayStorage is the storage used by the ClientChainGateway contract. It inherits from
/// BootstrapStorage, since the Bootstrap contract upgrades itself to the ClientChainGateway contract in response to a
/// cross-chain message.
/// @dev This contract should contain state variables, events and errors exclusively owned by
/// ClientChainGateway contract. Shared items should be kept in BootstrapStorage.
contract ClientChainGatewayStorage is BootstrapStorage {

    /// @notice Mapping to indicate whether a message to update the tvl limit is currently in flight.
    /// @dev This is used to ensure that a tvl increase and a total supply decrease aren't applied together, since
    /// we need to keep tvl <= total supply.
    mapping(address token => bool isInFlight) public tvlLimitIncreaseInFlight;

    /// @notice Mapping of owner addresses to their corresponding ExoCapsule contracts.
    mapping(address => IExoCapsule) public ownerToCapsule;

    /// @dev Mapping of request IDs to their corresponding request data.
    mapping(uint64 => bytes) internal _registeredRequests;

    /// @dev Mapping of request IDs to their corresponding request actions.
    mapping(uint64 => Action) internal _registeredRequestActions;

    /// @notice The address of the beacon chain oracle.
    address public immutable BEACON_ORACLE_ADDRESS;

    /// @notice The beacon proxy for the ExoCapsule contract.
    IBeacon public immutable EXO_CAPSULE_BEACON;

    /// @dev The address of the ETHPOS deposit contract.
    IETHPOSDeposit internal constant ETH_POS = IETHPOSDeposit(0x00000000219ab540356cBB839Cbe05303d7705Fa);

    /// @dev The gas limit for all the destination chains.
    uint128 internal constant DESTINATION_GAS_LIMIT = 500_000;

    /// @dev The msg.value for all the destination chains.
    uint128 internal constant DESTINATION_MSG_VALUE = 0;

    /// @dev Storage gap to allow for future upgrades.
    uint256[40] private __gap;

    /* ---------------------------- native restaking events ---------------------------- */
    /// @notice Emitted when a new ExoCapsule is created.
    /// @param owner Owner of the ExoCapsule.
    /// @param capsule Address of the ExoCapsule.
    event CapsuleCreated(address owner, address capsule);

    /// @notice Emitted when a staker stakes with a capsule.
    /// @param staker Address of the staker.
    /// @param capsule Address of the capsule.
    event StakedWithCapsule(address staker, address capsule);

    /* ----------------------------- restaking events     ------------------------------ */

    /// Emitted when a claim is successful.
    /// @param token Address of the token.
    /// @param recipient Address of the recipient.
    /// @param amount Amount of @param token claimed.
    event ClaimSucceeded(address token, address recipient, uint256 amount);

    /// @notice Emitted upon reward withdrawal response from Exocore.
    /// @param success Whether the withdrawal was successful.
    /// @param token Address of the token.
    /// @param withdrawer Address of the withdrawer.
    /// @param amount Amount of @param token withdrawn.
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);

    /// @notice Emitted when the gateway finishes processing a request.
    /// @param action The action of the request.
    /// @param requestId The ID of the request.
    /// @param success Whether the request was successful on Exocore.
    event RequestFinished(Action indexed action, uint64 indexed requestId, bool indexed success);

    /* -------------------------------------------------------------------------- */
    /*                                   Errors                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Error thrown when the ExoCapsule does not exist.
    error CapsuleNotExist();

    /// @notice Initializes the ClientChainGatewayStorage contract.
    /// @param exocoreChainId_ The chain ID of the Exocore chain.
    /// @param beaconOracleAddress_ The address of the beacon chain oracle.
    /// @param vaultBeacon_ The address of the beacon for the vault proxy.
    /// @param exoCapsuleBeacon_ The address of the beacon for the ExoCapsule proxy.
    /// @param beaconProxyBytecode_ The address of the beacon proxy bytecode contract.
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

    /// @dev Returns the ExoCapsule for the given owner, if it exists. Fails if the ExoCapsule does not exist.
    /// @param owner The owner of the ExoCapsule.
    function _getCapsule(address owner) internal view returns (IExoCapsule) {
        IExoCapsule capsule = ownerToCapsule[owner];
        if (address(capsule) == address(0)) {
            revert CapsuleNotExist();
        }
        return capsule;
    }

}
