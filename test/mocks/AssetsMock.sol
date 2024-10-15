// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// import "forge-std/console.sol";
import {IAssets} from "src/interfaces/precompiles/IAssets.sol";

contract AssetsMock is IAssets {

    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address constant VIRTUAL_STAKED_BTC_ADDRESS = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    uint32 internal constant clientBtcChainId = 111;

    mapping(uint32 => mapping(bytes => mapping(bytes => uint256))) public principalBalances;
    mapping(bytes => mapping(bytes => bool)) public inValidatorSet;

    uint32[] internal chainIds;
    mapping(uint32 chainId => bool registered) public isRegisteredChain;
    mapping(uint32 chainId => mapping(bytes token => bool registered)) public isRegisteredToken;

    constructor(uint32 clientChainId) {
        isRegisteredChain[clientChainId] = true;
        chainIds.push(clientChainId);
    }

    function depositLST(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata stakerAddress,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(assetsAddress.length == 32, "invalid asset address");

        if (clientChainLzId != clientBtcChainId) {
            require(stakerAddress.length == 32, "invalid staker address");
        }

        // Validate the asset address
        // If the assetsAddress is not the virtual ETH/BTC address, check if the token is registered
        bool notEth = bytes32(assetsAddress) != bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS));
        bool notBtc = bytes32(assetsAddress) != bytes32(bytes20(VIRTUAL_STAKED_BTC_ADDRESS));

        if (notEth && notBtc) {
            require(isRegisteredToken[clientChainLzId][assetsAddress], "the token not registered");
        }

        principalBalances[clientChainLzId][assetsAddress][stakerAddress] += opAmount;
        return (true, principalBalances[clientChainLzId][assetsAddress][stakerAddress]);
    }

    function depositNST(
        uint32 clientChainLzId,
        bytes calldata validatorPubkey,
        bytes calldata stakerAddress,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(stakerAddress.length == 32, "invalid staker address");

        bytes memory nstAddress = abi.encodePacked(bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)));
        principalBalances[clientChainLzId][nstAddress][stakerAddress] += opAmount;
        inValidatorSet[stakerAddress][validatorPubkey] = true;
        return (true, principalBalances[clientChainLzId][nstAddress][stakerAddress]);
    }

    function withdrawLST(
        uint32 clientChainLzId,
        bytes calldata assetsAddress,
        bytes calldata withdrawer,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(assetsAddress.length == 32, "invalid asset address");
        require(withdrawer.length == 32, "invalid staker address");

        bytes32 assetAddressBytes32 = bytes32(assetsAddress);
        bool isEth = assetAddressBytes32 == bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS));
        bool isBtc = assetAddressBytes32 == bytes32(bytes20(VIRTUAL_STAKED_BTC_ADDRESS));

        // Disallow ETH withdrawals or non-registered tokens (except BTC)
        if (isEth || (!isRegisteredToken[clientChainLzId][assetsAddress] && !isBtc)) {
            return (false, 0);
        }

        if (opAmount > principalBalances[clientChainLzId][assetsAddress][withdrawer]) {
            return (false, 0);
        }

        principalBalances[clientChainLzId][assetsAddress][withdrawer] -= opAmount;

        return (true, principalBalances[clientChainLzId][assetsAddress][withdrawer]);
    }

    function withdrawNST(
        uint32 clientChainLzId,
        bytes calldata validatorPubkey,
        bytes calldata withdrawer,
        uint256 opAmount
    ) external returns (bool success, uint256 latestAssetState) {
        require(withdrawer.length == 32, "invalid staker address");

        bytes memory nstAddress = abi.encodePacked(bytes32(bytes20(VIRTUAL_STAKED_ETH_ADDRESS)));
        if (opAmount > principalBalances[clientChainLzId][nstAddress][withdrawer]) {
            return (false, 0);
        }
        principalBalances[clientChainLzId][nstAddress][withdrawer] -= opAmount;
        inValidatorSet[withdrawer][validatorPubkey] = false;
        return (true, principalBalances[clientChainLzId][nstAddress][withdrawer]);
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

    function registerToken(
        uint32 clientChainId,
        bytes calldata token,
        uint8 decimals,
        string calldata name,
        string calldata metaData,
        string calldata oracleInfo
    ) external returns (bool success) {
        if (!isRegisteredChain[clientChainId]) {
            // chain not registered
            return false;
        }

        if (isRegisteredToken[clientChainId][token]) {
            // token already registered
            return false;
        }
        isRegisteredToken[clientChainId][token] = true;
        return true;
    }

    function updateToken(uint32 clientChainId, bytes calldata token, string calldata metaData)
        external
        returns (bool success)
    {
        if (!isRegisteredChain[clientChainId]) {
            // chain not registered
            return false;
        }

        if (!isRegisteredToken[clientChainId][token]) {
            // token not registered
            return false;
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

    function isRegisteredClientChain(uint32 clientChainID) external view returns (bool, bool) {
        return (true, isRegisteredChain[clientChainID]);
    }

}
