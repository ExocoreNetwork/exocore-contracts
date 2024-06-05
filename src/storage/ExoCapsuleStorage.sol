pragma solidity ^0.8.19;

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";

import {IBeaconChainOracle} from "@beacon-oracle/contracts/src/IBeaconChainOracle.sol";

contract ExoCapsuleStorage {

    // solhint-disable-next-line contract-name-camelcase
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
    uint256 public constant BEACON_CHAIN_GENESIS_TIME = 1_606_824_023;
    uint256 internal constant VERIFY_BALANCE_UPDATE_WINDOW_SECONDS = 4.5 hours;

    uint256 public principleBalance;
    uint256 public withdrawableBalance;
    address public capsuleOwner;
    INativeRestakingController public gateway;
    IBeaconChainOracle public beaconOracle;

    mapping(bytes32 pubkey => Validator validator) internal _capsuleValidators;
    mapping(uint256 index => bytes32 pubkey) internal _capsuleValidatorsByIndex;

    uint256[40] private __gap;

}
