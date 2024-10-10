pragma solidity ^0.8.19;

import {IReward} from "../../src/interfaces/precompiles/IReward.sol";

contract RewardMock is IReward {

    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) public rewardsOfAVS;
    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) public rewardsOfStaker;

    function submitReward(uint32 clientChainLzId, bytes calldata assetsAddress, bytes calldata avsId, uint256 amount)
        external
        returns (bool success, uint256 latestAssetState)
    {
        require(assetsAddress.length == 32, "invalid asset address");
        require(avsId.length == 32, "invalid avsId");
        rewardsOfAVS[clientChainLzId][assetsAddress][avsId] += amount;
        return (true, rewardsOfAVS[clientChainLzId][assetsAddress][avsId]);
    }

    function claimReward(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata withdrawer,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(withdrawer.length == 32, "invalid withdrawer address");
        require(rewardsOfStaker[clientChainLzId][assetsAddress][withdrawer] >= opAmount, "insufficient reward");
        rewardsOfStaker[clientChainLzId][assetsAddress][withdrawer] -= opAmount;
        return (true, rewardsOfStaker[clientChainLzId][assetsAddress][withdrawer]);
    }

    function distributeReward(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata avsId,
        bytes calldata staker,
        uint256 amount
    ) external returns (bool success, uint256 latestAssetState) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(staker.length == 32, "invalid staker address");
        require(avsId.length == 32, "invalid avsId");
        require(rewardsOfAVS[clientChainLzId][assetsAddress][avsId] >= amount, "insufficient reward");
        rewardsOfAVS[clientChainLzId][assetsAddress][avsId] -= amount;
        rewardsOfStaker[clientChainLzId][assetsAddress][staker] += amount;
        return (true, rewardsOfAVS[clientChainLzId][assetsAddress][avsId]);
    }

    function getRewardAmountForAVS(uint32 clientChainLzId, bytes calldata assetsAddress, bytes calldata avsId)
        external
        view
        returns (uint256)
    {
        return rewardsOfAVS[clientChainLzId][assetsAddress][avsId];
    }

    function getRewardAmountForStaker(uint32 clientChainLzId, bytes calldata assetsAddress, bytes calldata staker)
        external
        view
        returns (uint256)
    {
        return rewardsOfStaker[clientChainLzId][assetsAddress][staker];
    }

}
