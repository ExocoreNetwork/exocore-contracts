pragma solidity ^0.8.19;

import {IClaimReward} from "../../src/interfaces/precompiles/IClaimReward.sol";

contract ClaimRewardMock is IClaimReward {

    function claimReward(uint32 clientChainLzId, bytes memory assetsAddress, bytes memory withdrawer, uint256 opAmount)
        external
        pure
        returns (bool success, uint256 latestAssetState)
    {
        require(clientChainLzId >= 1, "Invalid client chain ID");
        require(assetsAddress.length == 32, "invalid asset address");
        require(withdrawer.length == 32, "invalid withdrawer address");
        require(opAmount > 0 && opAmount <= 1234, "Invalid reward amount");
        return (true, uint256(1234));
    }

}
