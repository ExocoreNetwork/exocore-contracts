pragma solidity ^0.8.19;

import {IDeposit} from "../../src/interfaces/precompiles/IDeposit.sol";
import {IWithdraw} from "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";

contract DepositWithdrawMock is IDeposit, IWithdraw {
    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) public principleBalances;

    function depositTo(uint32 clientChainLzId, bytes memory assetsAddress, bytes memory stakerAddress, uint256 opAmount)
        external
        returns (bool success, uint256 latestAssetState)
    {
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        principleBalances[clientChainLzId][assetsAddress][stakerAddress] += opAmount;

        return (true, principleBalances[clientChainLzId][assetsAddress][stakerAddress]);
    }

    function withdrawPrinciple(
        uint32 clientChainLzId,
        bytes memory assetsAddress,
        bytes memory withdrawer,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(withdrawer.length == 32, "invalid staker address");
        require(opAmount <= principleBalances[clientChainLzId][assetsAddress][withdrawer], "withdraw amount overflow");
        principleBalances[clientChainLzId][assetsAddress][withdrawer] -= opAmount;

        return (true, principleBalances[clientChainLzId][assetsAddress][withdrawer]);
    }

    function getPrincipleBalance(uint32 clientChainLzId, address token, address staker) public view returns (uint256) {
        return principleBalances[clientChainLzId][_addressToBytes(token)][_addressToBytes(staker)];
    }

    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }
}
