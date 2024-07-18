// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/console.sol";
import {IAssets} from "src/interfaces/precompiles/IAssets.sol";

contract AssetsMock is IAssets {

    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address constant VIRTUAL_STAKED_BTC_ADDRESS = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    uint32 internal constant clientBtcChainId = 111;

    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) public principalBalances;

    uint32[] internal chainIds;
    mapping(uint32 chainId => bool registered) public isRegisteredChain;
    mapping(uint32 chainId => mapping(bytes token => bool registered)) public isRegisteredToken;

    function depositTo(uint32 clientChainLzId, bytes memory assetsAddress, bytes memory stakerAddress, uint256 opAmount)
        external
        returns (bool success, uint256 latestAssetState)
    {
        require(assetsAddress.length == 32, "invalid asset address");

        console.log("stakerAddress len: ", stakerAddress.length);

        if (clientChainLzId != clientBtcChainId) {
            require(stakerAddress.length == 32, "invalid staker address");
        }

        // Validate the asset address
        // If the assetsAddress is not the virtual ETH/BTC address, check if the token is registered
        bool notEth = bytes32(assetsAddress) != bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS));
        bool notBtc = bytes32(assetsAddress) != bytes32(bytes20(VIRTUAL_STAKED_BTC_ADDRESS));
        if (notEth && notBtc) {
            console.log("notEth ", notEth, " notBtc", notBtc);
            require(isRegisteredToken[clientChainLzId][assetsAddress], "the token not registered");
        }

        principalBalances[clientChainLzId][assetsAddress][stakerAddress] += opAmount;
        console.log("principalBalances: ", opAmount);
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

    function registerClientChain(
        uint32 clientChainId,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) external returns (bool) {
        if (!isRegisteredChain[clientChainId]) {
            isRegisteredChain[clientChainId] = true;
            chainIds.push(clientChainId);
        }
        return true;
    }

    function registerToken(
        uint32 clientChainId,
        bytes calldata token,
        uint8 decimals,
        uint256 tvlLimit,
        string calldata name,
        string calldata metaData
    ) external returns (bool) {
        require(isRegisteredChain[clientChainId], "the chain is not registered before");

        if (!isRegisteredToken[clientChainId][token]) {
            isRegisteredToken[clientChainId][token] = true;
        }

        return true;
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

}
