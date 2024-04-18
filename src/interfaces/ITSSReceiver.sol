pragma solidity ^0.8.19;

interface ITSSReceiver {
    /**
     * @dev the interchain message sent from client chain Gateway or received from Exocore validator set for cross-chain communication.
     * @param dstChainID - testination chain ID.
     * @param dstAddress - destination contract address that would receive the interchain message.
     * @param payload - actual payload for receiver.
     * @param refundAddress - address used for refundding.
     * @param interchainFuelAddress - address that would pay for interchain costs.
     * @param params - custom params for extension.
     */
    struct InterchainMsg {
        uint32 srcChainID;
        bytes srcAddress;
        uint32 dstChainID;
        bytes dstAddress;
        uint64 nonce;
        bytes payload;
    }

    function receiveInterchainMsg(InterchainMsg calldata _msg, bytes memory signature) external;

    error UnauthorizedSigner();
    event MessageProcessed(
        uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload
    );
    event MessageFailed(
        uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload, bytes _reason
    );
}
