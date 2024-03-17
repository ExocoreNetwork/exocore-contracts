pragma solidity ^0.8.19;

import {IWithdrawPrinciple} from "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../../src/interfaces/precompiles/IDeposit.sol";
import "./DepositMock.sol";

contract WithdrawPrincipleMock is IWithdrawPrinciple {
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
        DepositMock(DEPOSIT_PRECOMPILE_ADDRESS).withdrawPrinciple(clientChainLzId, assetsAddress, withdrawer, opAmount);
        return (success, principleBalances[clientChainLzId][assetsAddress][withdrawer]);
    }
}