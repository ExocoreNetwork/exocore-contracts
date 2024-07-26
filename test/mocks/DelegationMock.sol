pragma solidity ^0.8.19;

import {ASSETS_PRECOMPILE_ADDRESS, IAssets} from "../../src/interfaces/precompiles/IAssets.sol";
import {IDelegation} from "../../src/interfaces/precompiles/IDelegation.sol";
import {AssetsMock} from "./AssetsMock.sol";

contract DelegationMock is IDelegation {

    mapping(bytes => mapping(bytes => mapping(uint32 => mapping(bytes => uint256)))) public delegateTo;
    mapping(uint32 clientChainId => mapping(bytes staker => bytes operator)) public stakerToOperator;
    mapping(uint32 chainId => bool registered) isRegisteredChain;

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
        if (!AssetsMock(ASSETS_PRECOMPILE_ADDRESS).isRegisteredChain(clientChainLzId)) {
            return false;
        }
        if (operatorAddr.length != 42) {
            return false;
        }
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
        if (!AssetsMock(ASSETS_PRECOMPILE_ADDRESS).isRegisteredChain(clientChainLzId)) {
            return false;
        }
        if (operatorAddr.length != 42) {
            return false;
        }
        if (opAmount > delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress]) {
            return false;
        }
        delegateTo[stakerAddress][operatorAddr][clientChainLzId][assetsAddress] -= opAmount;
        emit UndelegateRequestProcessed(
            clientChainLzId, lzNonce, assetsAddress, stakerAddress, string(operatorAddr), opAmount
        );

        return true;
    }

    function associateOperatorWithStaker(uint32 clientChainId, bytes memory staker, bytes memory operator)
        external
        returns (bool success)
    {
        if (!AssetsMock(ASSETS_PRECOMPILE_ADDRESS).isRegisteredChain(clientChainId)) {
            return false;
        }
        if (stakerToOperator[clientChainId][staker].length > 0) {
            return false;
        }
        stakerToOperator[clientChainId][staker] = operator;

        return true;
    }

    function dissociateOperatorFromStaker(uint32 clientChainId, bytes memory staker) external returns (bool success) {
        if (!AssetsMock(ASSETS_PRECOMPILE_ADDRESS).isRegisteredChain(clientChainId)) {
            return false;
        }
        if (stakerToOperator[clientChainId][staker].length == 0) {
            return false;
        }

        delete stakerToOperator[clientChainId][staker];

        return true;
    }

    function getDelegateAmount(address delegator, string memory operator, uint32 clientChainLzId, address token)
        public
        view
        returns (uint256)
    {
        return delegateTo[_addressToBytes(delegator)][bytes(operator)][clientChainLzId][_addressToBytes(token)];
    }

    function getAssociatedOperator(uint32 clientChainId, bytes memory staker)
        external
        view
        returns (bytes memory operator)
    {
        return stakerToOperator[clientChainId][staker];
    }

    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }

}
