// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title GatewayStorage
/// @notice Storage used by both ends of the gateway contract.
/// @dev This contract is used as the base storage and is inherited by the storage for Bootstrap and ExocoreGateway.
contract GatewayStorage {

    /// @notice Enum representing various actions that can be performed.
    enum Action {
        REQUEST_DEPOSIT,
        REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE,
        REQUEST_WITHDRAW_REWARD_FROM_EXOCORE,
        REQUEST_DELEGATE_TO,
        REQUEST_UNDELEGATE_FROM,
        REQUEST_DEPOSIT_THEN_DELEGATE_TO,
        REQUEST_MARK_BOOTSTRAP,
        REQUEST_ADD_WHITELIST_TOKENS,
        REQUEST_ASSOCIATE_OPERATOR,
        REQUEST_DISSOCIATE_OPERATOR,
        RESPOND
    }
    /// @notice the human readable prefix for Exocore bech32 encoded address.

    bytes public constant EXO_ADDRESS_PREFIX = bytes("exo1");

    /// @dev Mapping of actions to their corresponding function selectors.
    mapping(Action => bytes4) internal _whiteListFunctionSelectors;

    /// @dev Mapping to track inbound nonces for each chain and sender.
    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) public inboundNonce;

    /// @dev Storage gap to allow for future upgrades.
    uint256[40] private __gap;

    /// @notice Emitted when a message is sent through the gateway.
    /// @param act The action being performed.
    /// @param packetId The unique identifier for the packet.
    /// @param nonce The nonce associated with the message.
    /// @param nativeFee The native fee paid for the message.
    event MessageSent(Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    /// @notice Error thrown when an unsupported request is made.
    /// @param act The unsupported action.
    error UnsupportedRequest(Action act);

    /// @notice Error thrown when a message is received from an unexpected source chain.
    /// @param unexpectedSrcEndpointId The unexpected source chain ID.
    error UnexpectedSourceChain(uint32 unexpectedSrcEndpointId);

    /// @notice Error thrown when the inbound nonce is not as expected.
    /// @param expectedNonce The expected nonce.
    /// @param actualNonce The actual nonce received.
    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);

    /// @notice Ensures the provided address is a valid exo Bech32 encoded address.
    /// @param addressToValidate The address to check.
    modifier isValidBech32Address(string calldata addressToValidate) {
        require(isValidExocoreAddress(addressToValidate), "BootstrapStorage: invalid bech32 encoded Exocore address");
        _;
    }

    /// @notice Checks if the provided string is a valid Exocore address.
    /// @param addressToValidate The string to check.
    /// @return True if the string is valid, false otherwise.
    /// @dev Since implementation of bech32 is difficult in Solidity, this function only
    /// checks that the address is 42 characters long and starts with "exo1".
    function isValidExocoreAddress(string calldata addressToValidate) public pure returns (bool) {
        bytes memory stringBytes = bytes(addressToValidate);
        if (stringBytes.length != 42) {
            return false;
        }
        for (uint256 i = 0; i < EXO_ADDRESS_PREFIX.length; i++) {
            if (stringBytes[i] != EXO_ADDRESS_PREFIX[i]) {
                return false;
            }
        }

        return true;
    }

    /// @notice Verifies and updates the inbound nonce for a given source chain and address.
    /// @dev This function reverts if the nonce is not as expected.
    /// @param srcChainId The ID of the source chain.
    /// @param srcAddress The address of the sender on the source chain.
    /// @param nonce The nonce to be verified and updated.
    function _verifyAndUpdateNonce(uint32 srcChainId, bytes32 srcAddress, uint64 nonce) internal {
        uint64 expectedNonce = inboundNonce[srcChainId][srcAddress] + 1;
        if (nonce != expectedNonce) {
            revert UnexpectedInboundNonce(expectedNonce, nonce);
        }
        inboundNonce[srcChainId][srcAddress] = nonce;
    }

}
