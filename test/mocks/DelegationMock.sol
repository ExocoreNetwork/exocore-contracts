pragma solidity ^0.8.19;

import {IDelegation} from "../../src/interfaces/precompiles/IDelegation.sol";

contract DelegationMock is IDelegation {
    mapping(bytes => mapping(bytes => mapping(uint16 => mapping(bytes => uint256)))) delegateTo;
    function delegateToThroughClientChain(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        bytes memory operatorAddr,
        uint256 opAmount
    )
        external
        returns(bool success)
    {
        delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress] += opAmount;
    }

    function undelegateFromThroughClientChain(
        uint16 clientChainLzId,
        uint64 lzNonce,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        bytes memory operatorAddr,
        uint256 opAmount
    )
        external
        returns(bool success)
    {
        require(opAmount <= delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress], "amount overflow");
        delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress] -= opAmount;
    }
}