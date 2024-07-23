pragma solidity ^0.8.19;

import {IDelegation} from "../../src/interfaces/precompiles/IDelegation.sol";

contract DelegationMock is IDelegation {

    mapping(bytes => mapping(bytes => mapping(uint32 => mapping(bytes => uint256)))) public delegateTo;
    mapping(uint32 clientChainId => mapping(bytes staker => bytes operator)) public stakerToOperator;

    event DelegateRequestProcessed(
        uint32 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );
    event UndelegateRequestProcessed(
        uint32 clientChainLzId,
        uint64 lzNonce,
        bytes assetsAddress,
        bytes stakerAddress,
        string operatorAddr,
        uint256 opAmount
    );

    function delegateToThroughClientChain(
        uint32 clientChainLzId,
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

        return true;
    }

    function undelegateFromThroughClientChain(
        uint32 clientChainLzId,
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

        return true;
    }

    function associateOperatorWithStaker(uint32 clientChainId, bytes memory staker, bytes memory operator) external returns (bool success) {
        stakerToOperator[clientChainId][staker] = operator;
    }

    function dissociateOperatorFromStaker(uint32 clientChainId, bytes memory staker) external returns (bool success) {
        require(stakerToOperator[clientChainId][staker].length != 0, "staker has not been associated with any operator");

        delete stakerToOperator[clientChainId][staker];
    }

    function getDelegateAmount(address delegator, string memory operator, uint32 clientChainLzId, address token)
        public
        view
        returns (uint256)
    {
        return delegateTo[_addressToBytes(delegator)][bytes(operator)][clientChainLzId][_addressToBytes(token)];
    }

    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }

}
