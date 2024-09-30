pragma solidity ^0.8.19;

import {IReward} from "../../src/interfaces/precompiles/IReward.sol";

contract RewardMock is IReward {

    function submitReward(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata avsId,
        uint256 amount
    ) external returns (bool success, uint256 latestAssetState) {
        return (true, uint256(1234));
    }

    function claimReward(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata withdrawer,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(withdrawer.length == 32, "invalid withdrawer address");
        return (true, uint256(1234));
    }

}
