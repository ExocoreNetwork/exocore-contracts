pragma solidity ^0.8.19;

import {IDeposit} from "../../src/interfaces/precompiles/IDeposit.sol";
import "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "./WithdrawPrincipleMock.sol";

contract DepositMock is IDeposit {
    mapping(uint16 => mapping(bytes => mapping(bytes => uint256))) principleBalances;
    function depositTo(
        uint16 clientChainLzId,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        uint256 opAmount
    ) 
        external 
        returns (bool success,uint256 latestAssetState) 
    {
        principleBalances[clientChainLzId][assetsAddress][stakerAddress] += opAmount;
        WithdrawPrincipleMock(WITHDRAW_PRECOMPILE_ADDRESS).depositTo(clientChainLzId, assetsAddress, stakerAddress, opAmount);
        return (success, principleBalances[clientChainLzId][assetsAddress][stakerAddress]);
    }

    function withdrawPrinciple(
        uint16 clientChainLzId,
        bytes memory assetsAddress,
        bytes memory withdrawer,
        uint256 opAmount
    ) 
        external 
        returns (bool success,uint256 latestAssetState) 
    {   
        require(opAmount <= principleBalances[clientChainLzId][assetsAddress][withdrawer], "withdraw amount overflow");
        principleBalances[clientChainLzId][assetsAddress][withdrawer] -= opAmount;
    }
}