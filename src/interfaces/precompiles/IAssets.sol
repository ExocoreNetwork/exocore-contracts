pragma solidity >=0.8.17;

/// @dev The Assets contract's address.
address constant ASSETS_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000804;

/// @dev The Assets contract's instance.
IAssets constant ASSETS_CONTRACT = IAssets(ASSETS_PRECOMPILE_ADDRESS);

/// @author Exocore Team
/// @title Assets Precompile Contract
/// @dev The interface through which solidity contracts will interact with assets module
/// @custom:address 0x0000000000000000000000000000000000000804
interface IAssets {

    /// TRANSACTIONS
    /// @dev deposit the client chain assets for the staker,
    /// that will change the state in deposit module
    /// Note that this address cannot be a module account.
    /// @param clientChainLzID The LzID of client chain
    /// @param assetsAddress The client chain asset address
    /// @param stakerAddress The staker address
    /// @param opAmount The amount to deposit
    function depositTo(uint32 clientChainLzID, bytes memory assetsAddress, bytes memory stakerAddress, uint256 opAmount)
        external
        returns (bool success, uint256 latestAssetState);

    /// TRANSACTIONS
    /// @dev withdraw To the staker, that will change the state in withdraw module
    /// Note that this address cannot be a module account.
    /// @param clientChainLzID The LzID of client chain
    /// @param assetsAddress The client chain asset Address
    /// @param withdrawAddress The withdraw address
    /// @param opAmount The withdraw amount
    function withdrawPrincipal(
        uint32 clientChainLzID,
        bytes memory assetsAddress,
        bytes memory withdrawAddress,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState);

    /// QUERIES
    /// @dev Returns the chain indices of the client chains.
    function getClientChains() external view returns (bool, uint32[] memory);

    /// TRANSACTIONS
    /// @dev register some client chain to allow token registration from that chain, staking
    /// from that chain, and other operations from that chain.
    /// @param clientChainLzID The LzID of client chain
    function registerClientChain(uint32 clientChainLzID) external returns (bool success);

    /// TRANSACTIONS
    /// @dev register unwhitelisted token addresses to exocore
    /// @param clientChainLzID The LzID of client chain
    /// @param tokens The token addresses that would be registered to exocore
    function registerTokens(uint32 clientChainLzID, bytes[] memory tokens) external returns (bool success);

}
