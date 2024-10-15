pragma solidity ^0.8.19;

import {ASSETS_PRECOMPILE_ADDRESS, IAssets} from "../../src/interfaces/precompiles/IAssets.sol";
import {IDelegation} from "../../src/interfaces/precompiles/IDelegation.sol";
import {AssetsMock} from "./AssetsMock.sol";

contract DelegationMock is IDelegation {

    mapping(bytes => mapping(bytes => mapping(uint32 => mapping(bytes => uint256)))) public delegateToRecords;
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

    function delegate(
        uint32 clientChainLzId,
        uint64 lzNonce,
        bytes calldata assetsAddress,
        bytes calldata stakerAddress,
        bytes calldata operatorAddr,
        uint256 opAmount
    ) external returns (bool success) {
        if (!AssetsMock(ASSETS_PRECOMPILE_ADDRESS).isRegisteredChain(clientChainLzId)) {
            return false;
        }
        if (operatorAddr.length != 42) {
            return false;
        }
        delegateToRecords[stakerAddress][operatorAddr][clientChainLzId][assetsAddress] += opAmount;
        emit DelegateRequestProcessed(
            clientChainLzId, lzNonce, assetsAddress, stakerAddress, string(operatorAddr), opAmount
        );

        return true;
    }

    function undelegate(
        uint32 clientChainLzId,
        uint64 lzNonce,
        bytes calldata assetsAddress,
        bytes calldata stakerAddress,
        bytes calldata operatorAddr,
        uint256 opAmount
    ) external returns (bool success) {
        if (!AssetsMock(ASSETS_PRECOMPILE_ADDRESS).isRegisteredChain(clientChainLzId)) {
            return false;
        }
        if (operatorAddr.length != 42) {
            return false;
        }
        if (opAmount > delegateToRecords[stakerAddress][operatorAddr][clientChainLzId][assetsAddress]) {
            return false;
        }
        delegateToRecords[stakerAddress][operatorAddr][clientChainLzId][assetsAddress] -= opAmount;
        emit UndelegateRequestProcessed(
            clientChainLzId, lzNonce, assetsAddress, stakerAddress, string(operatorAddr), opAmount
        );

        return true;
    }

    function associateOperatorWithStaker(uint32 clientChainId, bytes calldata staker, bytes calldata operator)
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

    function dissociateOperatorFromStaker(uint32 clientChainId, bytes calldata staker)
        external
        returns (bool success)
    {
        if (!AssetsMock(ASSETS_PRECOMPILE_ADDRESS).isRegisteredChain(clientChainId)) {
            return false;
        }
        if (stakerToOperator[clientChainId][staker].length == 0) {
            return false;
        }

        delete stakerToOperator[clientChainId][staker];

        return true;
    }

    function getDelegateAmount(address delegator, string calldata operator, uint32 clientChainLzId, address token)
        public
        view
        returns (uint256)
    {
        return delegateToRecords[_addressToBytes(delegator)][bytes(operator)][clientChainLzId][_addressToBytes(token)];
    }

    function getAssociatedOperator(uint32 clientChainId, bytes calldata staker)
        external
        view
        returns (bytes memory operator)
    {
        return stakerToOperator[clientChainId][staker];
    }

    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }

    function delegateToThroughBtcGateway(
        uint32 clientChainId,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        bytes memory operatorAddr,
        uint256 opAmount
    ) external returns (bool success) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        require(operatorAddr.length == 42, "invalid operator address");
        delegateToRecords[stakerAddress][operatorAddr][clientChainId][assetsAddress] += opAmount;
        uint64 Nonce = 1;
        emit DelegateRequestProcessed(
            clientChainId, Nonce, assetsAddress, stakerAddress, string(operatorAddr), opAmount
        );
        return true;
    }

    function undelegateFromThroughBtcGateway(
        uint32 clientChainId,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        bytes memory operatorAddr,
        uint256 opAmount
    ) external returns (bool success) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        require(operatorAddr.length == 42, "invalid operator address");
        require(
            opAmount <= delegateToRecords[stakerAddress][operatorAddr][clientChainId][assetsAddress], "amount overflow"
        );
        delegateToRecords[stakerAddress][operatorAddr][clientChainId][assetsAddress] -= opAmount;
        uint64 lzNonce = 12;
        emit UndelegateRequestProcessed(
            clientChainId, lzNonce, assetsAddress, stakerAddress, string(operatorAddr), opAmount
        );

        return true;
    }

}
