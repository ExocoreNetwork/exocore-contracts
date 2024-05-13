pragma solidity ^0.8.19;

import {IDeposit} from "../../src/interfaces/precompiles/IDeposit.sol";
import "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "./WithdrawPrincipleMock.sol";

contract DepositMock is IDeposit {
    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) principleBalances;
    function depositTo(
        uint32 clientChainLzId,
        bytes memory assetsAddress,
        bytes memory stakerAddress,
        uint256 opAmount
    ) 
        external 
        returns (bool success,uint256 latestAssetState) 
    {   
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        principleBalances[clientChainLzId][assetsAddress][stakerAddress] += opAmount;
        WithdrawPrincipleMock(WITHDRAW_PRECOMPILE_ADDRESS).depositTo(clientChainLzId, assetsAddress, stakerAddress, opAmount);
        return (success, principleBalances[clientChainLzId][assetsAddress][stakerAddress]);
    }

    function withdrawPrinciple(
        uint32 clientChainLzId,
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