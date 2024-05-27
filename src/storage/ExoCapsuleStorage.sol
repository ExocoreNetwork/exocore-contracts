pragma solidity ^0.8.19;

import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";

import {IBeaconChainOracle} from "@beacon-oracle/contracts/src/IBeaconChainOracle.sol";

contract ExoCapsuleStorage {
    enum VALIDATOR_STATUS {
        UNREGISTERED, // the validator has not been registered in this ExoCapsule
        REGISTERED, // staked on ethpos and withdrawal credentials are pointed to the ExoCapsule
        WITHDRAWN // withdrawn from the Beacon Chain
    }

    struct Validator {
        // index of the validator in the beacon chain
        uint256 validatorIndex;
        // amount of beacon chain ETH restaked on EigenLayer in gwei
        uint64 restakedBalanceGwei;
        //timestamp of the validator's most recent balance update
        uint256 mostRecentBalanceUpdateTimestamp;
        // status of the validator
        VALIDATOR_STATUS status;
    }

    // constant state variables
    address public constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    uint256 public constant BEACON_CHAIN_GENESIS_TIME = 1606824023;
    uint256 internal constant VERIFY_BALANCE_UPDATE_WINDOW_SECONDS = 4.5 hours;
    uint256 constant GWEI_TO_WEI = 1e9;
    uint64 constant MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR = 32e9;

    /**
     * @notice The latest timestamp at which the capsule owner withdrew the balance of the capsule, via calling `withdrawBeforeRestaking`.
     * @dev This variable is only updated when the `withdrawBeforeRestaking` function is called, which can only occur before `hasRestaked` is set to true for this capsule.
     * Proofs for this capsule are only valid against Beacon Chain state roots corresponding to timestamps after the stored `mostRecentWithdrawalTimestamp`.
     */
    uint256 public mostRecentWithdrawalTimestamp;
    /// @notice an indicator of whether or not the capsule owner has ever "fully restaked" by successfully calling `verifyCorrectWithdrawalCredentials`.
    bool public hasRestaked;

    uint256 public principleBalance;
    /// @notice the amount of execution layer ETH in this contract that is staked in(i.e. withdrawn from the Beacon Chain but not from Exocore)
    uint256 public withdrawableBalance;
    /// @notice This variable tracks any ETH deposited into this contract via the `receive` fallback function
    uint256 public nonBeaconChainETHBalance;
    address public capsuleOwner;
    INativeRestakingController public gateway;
    IBeaconChainOracle public beaconOracle;

    mapping(bytes32 pubkey => Validator validator) _capsuleValidators;
    mapping(uint256 index => bytes32 pubkey) _capsuleValidatorsByIndex;
    /// @notice This is a mapping of validatorPubkeyHash to timestamp to whether or not they have proven a withdrawal for that timestamp
    mapping(bytes32 => mapping(uint256 => bool)) public provenWithdrawal;

    uint256[40] private __gap;
}
