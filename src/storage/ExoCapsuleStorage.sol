pragma solidity ^0.8.19;

contract ExoCapsuleStorage {
    enum VALIDATOR_STATUS {
        UNREGISTERED, // the validator has not been registered in this ExoCapsule
        REGISTERED, // staked on ethpos and withdrawal credentials are pointed to the ExoCapsule
        EXITED // withdrawn from the Beacon Chain
    }

    struct Validator {
        // index of the validator in the beacon chain
        uint64 validatorIndex;
        // amount of beacon chain ETH restaked on EigenLayer in gwei
        uint64 restakedBalanceGwei;
        //timestamp of the validator's most recent balance update
        uint64 mostRecentBalanceUpdateTimestamp;
        // status of the validator
        VALIDATOR_STATUS status;
    }

    address public constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    uint64 public constant BEACON_CHAIN_GENESIS_TIME = 1606824023;

    address payable exocoreValidatorSetAddress;
    mapping(bytes32 pubkey => Validator validator) _capsuleValidators;
    mapping(uint64 index => bytes32 pubkey) _capsuleValidatorsByIndex;

    uint256[40] private __gap;
}