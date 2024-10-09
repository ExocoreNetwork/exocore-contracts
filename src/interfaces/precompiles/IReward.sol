// SPDX-License-Identifier: MIT
pragma solidity >=0.8.17;

/// TODO: we might remove this precompile contract and merge it into assets precompile
/// if we decide to handle reward withdrawal request by assets precompile

/// @dev The claimReward contract's address.
address constant REWARD_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000806;

/// @dev The claimReward contract's instance.
IReward constant REWARD_CONTRACT = IReward(REWARD_PRECOMPILE_ADDRESS);

/// @author Exocore Team
/// @title ClaimReward Precompile Contract
/// @dev The interface through which solidity contracts will interact with ClaimReward
/// @custom:address 0x0000000000000000000000000000000000000806
interface IReward {

    function submitReward(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata avsId,
        uint256 amount
    ) external returns (bool success, uint256 latestAssetState);

    /// TRANSACTIONS
    /// @dev ClaimReward To the staker, that will change the state in reward module
    /// Note that this address cannot be a module account.
    /// @param clientChainLzId The lzId of client chain
    /// @param assetsAddress The client chain asset Address
    /// @param withdrawRewardAddress The claim reward address
    /// @param opAmount The reward amount
    function claimReward(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata withdrawRewardAddress,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState);

}
