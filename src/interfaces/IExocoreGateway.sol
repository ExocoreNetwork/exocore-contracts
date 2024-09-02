// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {IOAppReceiver} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppReceiver.sol";

/// @title IExocoreGateway
/// @author ExocoreNetwork
/// @notice IExocoreGateway is the interface for the ExocoreGateway contract. It provides a set of functions for
/// ExocoreGateway operations.
/// @dev It is deployed on the Exocore end and is designed to interact with other chains,
/// as well as precompiles on the Exocore chain in response to messages from other chains.
interface IExocoreGateway is IOAppReceiver, IOAppCore {

    /// @notice Calculates the native fee for sending a message with specific options.
    /// @param srcChainid The chain id of the source chain, from which a message was received,
    /// and to which a response is being sent.
    /// @param _message The message for which the fee is being calculated.
    /// @return nativeFee The calculated native fee for the given message.
    function quote(uint32 srcChainid, bytes memory _message) external view returns (uint256 nativeFee);

    /// @notice Registers the @param clientChainId and other meta data to Exocore native module or update the client
    /// chain's meta data, if a chain identified by @param clientChainId already exists. Sets trusted @param peer to
    /// enable cross-chain communication.
    /// @param clientChainId The endpoint ID for client chain.
    /// @param peer The trusted remote contract address to be associated with the corresponding endpoint or some
    /// authorized signer that would be trusted for sending messages from/to source chain to/from this contract.
    /// @param addressLength The bytes length of address type on that client chain.
    /// @param name The name of client chain.
    /// @param metaInfo The arbitrary metadata for client chain.
    /// @param signatureType The cryptographic signature type that client chain supports.
    /// @dev Only the owner/admin of the OApp can call this function.
    /// @dev Indicates that the peer is trusted to send LayerZero messages to this OApp.
    /// @dev Peer is a bytes32 to accommodate non-evm chains.
    function registerOrUpdateClientChain(
        uint32 clientChainId,
        bytes32 peer,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) external;

    /// @notice Adds a list of whitelisted tokens to the client chain.
    /// @param clientChainId The LayerZero chain id of the client chain.
    /// @param tokens The list of token addresses to be whitelisted.
    /// @param decimals The list of token decimals, in the same order as the tokens list.
    /// @param tvlLimits The list of token TVL limits (typically max supply),in the same order as the tokens list.
    /// @param names The names of the tokens, in the same order as the tokens list.
    /// @param metaData The meta information of the tokens, in the same order as the tokens list.
    /// @dev The chain must be registered before adding tokens.
    function addOrUpdateWhitelistTokens(
        uint32 clientChainId,
        bytes32[] calldata tokens,
        uint8[] calldata decimals,
        uint256[] calldata tvlLimits,
        string[] calldata names,
        string[] calldata metaData
    ) external payable;

    /// @notice Marks the network as bootstrapped, on the client chain.
    /// @dev Causes an upgrade of the Bootstrap contract to the ClientChainGateway contract.
    /// @dev Only works if LZ infrastructure is set up and SetPeer has been called.
    /// @dev This is payable because it requires a fee to be paid to LZ.
    /// @param clientChainId The LayerZero chain id of the client chain.
    function markBootstrap(uint32 clientChainId) external payable;

}
