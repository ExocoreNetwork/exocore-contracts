pragma solidity ^0.8.19;

import {IDelegation} from "../../src/interfaces/precompiles/IDelegation.sol";

contract DelegationMock is IDelegation {
    mapping(bytes => mapping(bytes => mapping(uint16 => mapping(bytes => uint256)))) delegateTo;

    event DelegateRequestProcessed(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );
    event UndelegateRequestProcessed(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );

    function delegateToThroughClientChain(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        bytes memory operatorAddr,
        uint256 opAmount
    ) external returns (bool success) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        require(operatorAddr.length == 42, "invalid operator address");
        delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress] += opAmount;
        emit DelegateRequestProcessed(
            clientChainLzId, lzNonce, assetsAddress, stakerAddress, string(operatorAddr), opAmount
        );
    }

    function undelegateFromThroughClientChain(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        bytes memory operatorAddr,
        uint256 opAmount
    ) external returns (bool success) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        require(operatorAddr.length == 42, "invalid operator address");
        require(opAmount <= delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress], "amount overflow");
        delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress] -= opAmount;
        emit UndelegateRequestProcessed(
            clientChainLzId, lzNonce, assetsAddress, stakerAddress, string(operatorAddr), opAmount
        );
    }
}
