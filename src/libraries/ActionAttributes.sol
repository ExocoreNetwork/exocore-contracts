// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Action} from "../storage/GatewayStorage.sol";

library ActionAttributes {

    // Message length constants
    uint256 internal constant ASSET_OPERATION_LENGTH = 97;
    uint256 internal constant DELEGATION_OPERATION_LENGTH = 139;
    uint256 internal constant ASSOCIATE_OPERATOR_LENGTH = 75;
    uint256 internal constant DISSOCIATE_OPERATOR_LENGTH = 33;

    // Bitmaps for operation types
    uint256 internal constant ASSET_OPERATION = 1 << 0;
    uint256 internal constant STAKING_OPERATION = 1 << 1;
    uint256 internal constant PRINCIPAL_TYPE = 1 << 2;
    uint256 internal constant REWARD_TYPE = 1 << 3;
    uint256 internal constant WITHDRAWAL = 1 << 4;
    uint256 internal constant DEPOSIT = 1 << 5;
    uint256 internal constant BASIC_RESPONSE = 1 << 6;
    uint256 internal constant BALANCE_RESPONSE = 1 << 7;

    uint256 internal constant MESSAGE_LENGTH_MASK = 0xFF; // 8 bits for message length
    uint256 internal constant MESSAGE_LENGTH_SHIFT = 8;

    function getAttributes(Action action) internal pure returns (uint256) {
        uint256 attributes;
        uint256 messageLength;

        if (action == Action.REQUEST_DEPOSIT_LST || action == Action.REQUEST_DEPOSIT_NST) {
            attributes = ASSET_OPERATION | PRINCIPAL_TYPE | DEPOSIT | BALANCE_RESPONSE;
            messageLength = ASSET_OPERATION_LENGTH;
        } else if (action == Action.REQUEST_WITHDRAW_LST || action == Action.REQUEST_WITHDRAW_NST) {
            attributes = ASSET_OPERATION | PRINCIPAL_TYPE | WITHDRAWAL | BALANCE_RESPONSE;
            messageLength = ASSET_OPERATION_LENGTH;
        } else if (action == Action.REQUEST_CLAIM_REWARD) {
            attributes = ASSET_OPERATION | REWARD_TYPE | WITHDRAWAL | BALANCE_RESPONSE;
            messageLength = ASSET_OPERATION_LENGTH;
        } else if (action == Action.REQUEST_DELEGATE_TO || action == Action.REQUEST_UNDELEGATE_FROM) {
            attributes = STAKING_OPERATION | BASIC_RESPONSE;
            messageLength = DELEGATION_OPERATION_LENGTH;
        } else if (action == Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO) {
            attributes = STAKING_OPERATION | PRINCIPAL_TYPE | DEPOSIT | BALANCE_RESPONSE;
            messageLength = DELEGATION_OPERATION_LENGTH;
        } else if (action == Action.REQUEST_ASSOCIATE_OPERATOR) {
            attributes = STAKING_OPERATION | BASIC_RESPONSE;
            messageLength = ASSOCIATE_OPERATOR_LENGTH;
        } else if (action == Action.REQUEST_DISSOCIATE_OPERATOR) {
            attributes = STAKING_OPERATION | BASIC_RESPONSE;
            messageLength = DISSOCIATE_OPERATOR_LENGTH;
        } else {
            return 0;
        }

        return attributes | (messageLength << MESSAGE_LENGTH_SHIFT);
    }

    function isAssetOperationRequest(Action action) internal pure returns (bool) {
        return (getAttributes(action) & ASSET_OPERATION) != 0;
    }

    function isStakingOperationRequest(Action action) internal pure returns (bool) {
        return (getAttributes(action) & STAKING_OPERATION) != 0;
    }

    function expectBasicResponse(Action action) internal pure returns (bool) {
        return (getAttributes(action) & BASIC_RESPONSE) != 0;
    }

    function expectBalanceResponse(Action action) internal pure returns (bool) {
        return (getAttributes(action) & BALANCE_RESPONSE) != 0;
    }

    function isPrincipalType(Action action) internal pure returns (bool) {
        return (getAttributes(action) & PRINCIPAL_TYPE) != 0;
    }

    function isRewardType(Action action) internal pure returns (bool) {
        return (getAttributes(action) & REWARD_TYPE) != 0;
    }

    function isWithdrawal(Action action) internal pure returns (bool) {
        return (getAttributes(action) & WITHDRAWAL) != 0;
    }

    function isDeposit(Action action) internal pure returns (bool) {
        return (getAttributes(action) & DEPOSIT) != 0;
    }

    function getMessageLength(Action action) internal pure returns (uint256) {
        return (getAttributes(action) >> MESSAGE_LENGTH_SHIFT) & MESSAGE_LENGTH_MASK;
    }

}
