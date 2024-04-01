pragma solidity ^0.8.19;

import {IExoCapsule} from "./IExoCapsule.sol";

interface INativeRestakingController {
    /// *** function signatures for staker operations ***

    /**
     * @notice Ethereum native restaker should call this function to create owned ExoCapsule before staking to beacon chain.
     */
    function createExoCapsule() external;

    /**
     * @notice This is called to deposit ETH that is staked on Ethereum beacon chain to Exocore network to be restaked in future
     * @dev Before deposit, staker should have created the ExoCapsule that it owns and point the validator's withdrawal crendentials
     * to the ExoCapsule owned by staker.
     */
    function depositAsBeaconValidator(bytes32[] validatorContainer, IExoCapsule.WithdrawalContainerProof proof) external;

    /**
     * @notice After native restaker deposits and delegates on Exocore network, the restaker's principle balance could be influenced by
     * rewards/penalties/slashing from both Ethereum beacon chain and Exocore chain, so principle balance update owing to beacon chain
     * consensus should be accounted for by Exocore chain as well.
     */
    function commitBeaconBalanceDelta(bytes32[] validatorContainer, IExoCapsule.WithdrawalContainerProof proof) external;

    /**
     * @notice Client chain users call to withdraw principle from Exocore to client chain before they are granted to withdraw from the vault.
     * @dev This function should ask Exocore validator set for withdrawal grant. If Exocore validator set responds
     * with true or success, the corresponding assets should be unlocked to make them claimable by users themselves. Otherwise
     * these assets should remain locked.
     * @param token - The address of specific token that the user wants to withdraw from Exocore.
     * @param principleAmount - principle means the assets user deposits into Exocore for delegating and staking.
     * we suppose that After deposit, its amount could only remain unchanged or decrease owing to slashing, which means that direct
     * transfer of principle is not possible.
     */
    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external payable;

    function withdrawRewardFromExocore(address token, uint256 rewardAmount) external payable;

    /**
     * @notice Client chain users call to claim their unlocked assets from the vault.
     * @dev This function assumes that the claimable assets should have been unlocked before calling this.
     * @dev This function does not ask for grant from Exocore validator set.
     * @param token - The address of specific token that the user wants to claim from the vault.
     * @param amount - The amount of @param token that the user wants to claim from the vault.
     * @param recipient - The destination address that the assets would be transfered to.
     */
    function claim(address token, uint256 amount, address recipient) external;

    /// *** function signatures for commands of Exocore validator set forwarded by Gateway ***

    /**
     * @notice This should only be called by Exocore validator set through Gateway to update user's involved
     * lastly updated token balance.
     * @dev Only Exocore validato set could indirectly call this function through Gateway contract.
     * @dev This function could be called in two scenaries:
     * 1) Exocore validator set periodically calls this to update user principle and reward balance.
     * 2) Exocore validator set sends reponse for the request of withdrawPrincipleFromExocore and unlock part of
     * the vault assets and update user's withdrawable balance correspondingly.
     * @param info - The info needed for updating users balance.
     */
    function updateUsersBalances(UserBalanceUpdateInfo[] calldata info) external;
}
