pragma solidity ^0.8.19;

import {IAssets} from "src/interfaces/precompiles/IAssets.sol";

contract AssetsMock is IAssets {

    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) public principleBalances;

    uint32[] internal chainIds;
    mapping(uint32 chainId => bool registered) isRegisteredChain;
    mapping(uint32 chainId => mapping(bytes token => bool registered)) isRegisteredToken;

    function depositTo(uint32 clientChainLzId, bytes memory assetsAddress, bytes memory stakerAddress, uint256 opAmount)
        external
        returns (bool success, uint256 latestAssetState)
    {
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        if (bytes32(assetsAddress) != bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS))) {
            require(isRegisteredToken[clientChainLzId][assetsAddress], "the token is not registered before");
        }

        principleBalances[clientChainLzId][assetsAddress][stakerAddress] += opAmount;

        return (true, principleBalances[clientChainLzId][assetsAddress][stakerAddress]);
    }

    function withdrawPrinciple(
        uint32 clientChainLzId,
        bytes memory assetsAddress,
        bytes memory withdrawer,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(withdrawer.length == 32, "invalid staker address");
        if (bytes32(assetsAddress) != bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS))) {
            require(isRegisteredToken[clientChainLzId][assetsAddress], "the token is not registered before");
        }

        require(opAmount <= principleBalances[clientChainLzId][assetsAddress][withdrawer], "withdraw amount overflow");

        principleBalances[clientChainLzId][assetsAddress][withdrawer] -= opAmount;

        return (true, principleBalances[clientChainLzId][assetsAddress][withdrawer]);
    }

    function getClientChains() external view returns (bool, uint32[] memory) {
        return (true, chainIds);
    }

    function registerClientChain(uint32 chainId) external returns (bool) {
        require(!isRegisteredChain[chainId], "has already been registered");

        isRegisteredChain[chainId] = true;
        chainIds.push(chainId);
        return true;
    }

    function registerTokens(uint32 chainId, bytes[] memory tokens) external returns (bool) {
        require(isRegisteredChain[chainId], "the chain is not registered before");

        for (uint256 i; i < tokens.length; i++) {
            bytes memory token = tokens[i];
            require(token.length == 32, "token address with invalid length");
            require(!isRegisteredToken[chainId][token], "already registered token");

            isRegisteredToken[chainId][token] = true;
        }

        return true;
    }

    function getPrincipleBalance(uint32 clientChainLzId, bytes memory token, bytes memory staker) public view returns (uint256) {
        return principleBalances[clientChainLzId][token][staker];
    }

    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }

}
