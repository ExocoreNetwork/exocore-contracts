pragma solidity ^0.8.19;

import {IAssets} from "src/interfaces/precompiles/IAssets.sol";

contract AssetsMock is IAssets {

    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) public principalBalances;

    uint32[] internal chainIds;
    mapping(uint32 chainId => bool registered) public isRegisteredChain;
    mapping(uint32 chainId => mapping(bytes token => bool registered)) public isRegisteredToken;

    function depositTo(uint32 clientChainLzId, bytes memory assetsAddress, bytes memory stakerAddress, uint256 opAmount)
        external
        returns (bool success, uint256 latestAssetState)
    {
        require(assetsAddress.length == 32, "invalid asset address");
        require(stakerAddress.length == 32, "invalid staker address");
        if (bytes32(assetsAddress) != bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS))) {
            require(isRegisteredToken[clientChainLzId][assetsAddress], "the token is not registered before");
        }

        principalBalances[clientChainLzId][assetsAddress][stakerAddress] += opAmount;

        return (true, principalBalances[clientChainLzId][assetsAddress][stakerAddress]);
    }

    function withdrawPrincipal(
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

        require(opAmount <= principalBalances[clientChainLzId][assetsAddress][withdrawer], "withdraw amount overflow");

        principalBalances[clientChainLzId][assetsAddress][withdrawer] -= opAmount;

        return (true, principalBalances[clientChainLzId][assetsAddress][withdrawer]);
    }

    function getClientChains() external view returns (bool, uint32[] memory) {
        return (true, chainIds);
    }

    function registerOrUpdateClientChain(
        uint32 clientChainId,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) external returns (bool, bool) {
        bool updated = isRegisteredChain[clientChainId];
        if (!isRegisteredChain[clientChainId]) {
            isRegisteredChain[clientChainId] = true;
            chainIds.push(clientChainId);
        }
        return (true, updated);
    }

    function registerOrUpdateTokens(
        uint32 clientChainId,
        bytes calldata token,
        uint8 decimals,
        uint256 tvlLimit,
        string calldata name,
        string calldata metaData,
        string calldata oracleInfo
    ) external returns (bool success, bool updated) {
        require(isRegisteredChain[clientChainId], "the chain is not registered before");

        updated = isRegisteredToken[clientChainId][token];

        if (!updated) {
            isRegisteredToken[clientChainId][token] = true;
        }

        return (true, updated);
    }

    function getPrincipalBalance(uint32 clientChainLzId, bytes memory token, bytes memory staker)
        public
        view
        returns (uint256)
    {
        return principalBalances[clientChainLzId][token][staker];
    }

    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(addr)));
    }

    function isRegisteredClientChain(uint32 clientChainID) external view returns (bool, bool) {
        return (true, isRegisteredChain[clientChainID]);
    }

}
