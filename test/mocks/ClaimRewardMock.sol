pragma solidity ^0.8.19;

import {IClaimReward} from "../../src/interfaces/precompiles/IClaimReward.sol";

contract ClaimRewardMock is IClaimReward {
    function claimReward(
        uint16 clientChainLzId,
        bytes memory assetsAddress,
        bytes memory withdrawer,
        uint256 opAmount
    ) 
        external 
        returns (bool success,uint256 latestAssetState) 
    {   
        return (success, uint256(1234));
    }
}