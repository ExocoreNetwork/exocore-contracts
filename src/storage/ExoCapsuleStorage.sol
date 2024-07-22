// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";

import {IBeaconChainOracle} from "@beacon-oracle/contracts/src/IBeaconChainOracle.sol";

/// @title ExoCapsuleStorage
/// @author ExocoreNetwork
/// @notice The storage contract for the ExoCapsule contract.
contract ExoCapsuleStorage {

    /// @notice Enum representing the status of a validator.
    // solhint-disable-next-line contract-name-camelcase
    enum VALIDATOR_STATUS {
        UNREGISTERED, // the validator has not been registered in this ExoCapsule
        REGISTERED, // staked on ethpos and withdrawal credentials are pointed to the ExoCapsule
        WITHDRAWN // withdrawn from the Beacon Chain

    }

    /// @notice Struct representing a validator in the ExoCapsule.
    /// @param validatorIndex The index of the validator in the Beacon Chain.
    /// @param restakedBalanceGwei The amount of Beacon Chain ETH restaked on Exocore in gwei.
    /// @param mostRecentBalanceUpdateTimestamp The timestamp of the validator's most recent balance update.
    /// @param status The status of the validator.
    struct Validator {
        // index of the validator in the beacon chain
        uint256 validatorIndex;
        // amount of beacon chain ETH restaked on Exocore in gwei
        uint64 restakedBalanceGwei;
        //timestamp of the validator's most recent balance update
        uint256 mostRecentBalanceUpdateTimestamp;
        // status of the validator
        VALIDATOR_STATUS status;
    }

    // constant state variables
    /// @notice The address of the Beacon Chain's roots contract.
    address public constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice The genesis time of the Beacon Chain.
    uint256 public constant BEACON_CHAIN_GENESIS_TIME = 1_606_824_023;

    /// @notice The maximum time after the withdrawal proof timestamp that a withdrawal can be proven.
    uint256 internal constant VERIFY_BALANCE_UPDATE_WINDOW_SECONDS = 4.5 hours;

    /// @notice Conversion factor from gwei to wei.
    uint256 public constant GWEI_TO_WEI = 1e9;

    /// @notice The maximum amount of balance that a validator can restake, in gwei.
    uint64 public constant MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR = 32e9;

    /// @notice The principal balance of the ExoCapsule (TODO: which unit?)
    uint256 public principalBalance;

    /// @notice the amount of execution layer ETH in this contract that is staked in(i.e. withdrawn from the Beacon
    /// Chain but not from Exocore)
    uint256 public withdrawableBalance;

    /// @notice The amount of non-beacon chain ETH balance.
    /// @dev This variable tracks any ETH deposited into this contract via the `receive` fallback function
    uint256 public nonBeaconChainETHBalance;

    /// @notice The owner of the ExoCapsule.
    address public capsuleOwner;

    /// @notice The address of the NativeRestakingController contract.
    INativeRestakingController public gateway;

    /// @notice The address of the Beacon Chain Oracle contract.
    IBeaconChainOracle public beaconOracle;

    /// @dev Mapping of validator pubkey to their corresponding struct.
    mapping(bytes32 pubkey => Validator validator) internal _capsuleValidators;

    /// @dev Mapping of validator index to their corresponding pubkey.
    mapping(uint256 index => bytes32 pubkey) internal _capsuleValidatorsByIndex;

    /// @notice This is a mapping of validatorPubkeyHash to withdrawal index to whether or not they have proven a
    /// withdrawal
    mapping(bytes32 => mapping(uint256 => bool)) public provenWithdrawal;

    /// @dev Storage gap to allow for future upgrades.
    uint256[40] private __gap;

}
