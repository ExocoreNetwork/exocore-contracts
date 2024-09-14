// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Action} from "../storage/GatewayStorage.sol";

library ActionAttributes {

    // Bitmaps for operation types
    uint256 internal constant ASSET_OPERATION = 1 << 0;
    uint256 internal constant STAKING_OPERATION = 1 << 1;
    uint256 internal constant PRINCIPAL_TYPE = 1 << 2;
    uint256 internal constant REWARD_TYPE = 1 << 3;
    uint256 internal constant WITHDRAWAL = 1 << 4;
    uint256 internal constant DEPOSIT = 1 << 5;
    uint256 internal constant BASIC_RESPONSE = 1 << 6;
    uint256 internal constant BALANCE_RESPONSE = 1 << 7;

    function getAttributes(Action action) internal pure returns (uint256) {
        if (action == Action.REQUEST_DEPOSIT_LST || action == Action.REQUEST_DEPOSIT_NST) {
            return ASSET_OPERATION | PRINCIPAL_TYPE | DEPOSIT | BALANCE_RESPONSE;
        } else if (action == Action.REQUEST_WITHDRAW_LST || action == Action.REQUEST_WITHDRAW_NST) {
            return ASSET_OPERATION | PRINCIPAL_TYPE | WITHDRAWAL | BALANCE_RESPONSE;
        } else if (action == Action.REQUEST_CLAIM_REWARD) {
            return ASSET_OPERATION | REWARD_TYPE | WITHDRAWAL | BALANCE_RESPONSE;
        } else if (action == Action.REQUEST_DELEGATE_TO || action == Action.REQUEST_UNDELEGATE_FROM) {
            return STAKING_OPERATION | BASIC_RESPONSE;
        } else if (action == Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO) {
            return ASSET_OPERATION | STAKING_OPERATION | PRINCIPAL_TYPE | DEPOSIT | BALANCE_RESPONSE;
        } else {
            return 0;
        }
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

}
