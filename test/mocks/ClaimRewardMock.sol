pragma solidity ^0.8.19;

import {IClaimReward} from "../../src/interfaces/precompiles/IClaimReward.sol";

contract ClaimRewardMock is IClaimReward {

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
