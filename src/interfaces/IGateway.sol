pragma solidity ^0.8.19;

interface IGateway {
    /**
     * @dev The interchain message sent from client chain Gateway or received from Exocore validator set for cross-chain communication.
     * @param dstChainID - Destination chain ID.
     * @param dstAddress - Destination contract address that would receive the interchain message.
     * @param payload - Actual payload for receiver.
     * @param refundAddress - Address used for refundding.
     * @param interchainFuelAddress - Address that would pay for interchain costs.
     * @param params - Custom params for extension.
     */
    struct InterchainMsg {
        uint16  dstChainID;
        bytes  dstAddress;
        bytes payload;
        address payable refundAddress;
        address payable interchainFuelAddress;
        bytes params;
    }

    /**
     * @dev Emitted when sending interchain message from Gateway or receiving from Exocore validator set. 
     * @param dstChainID - Destination chain ID.
     * @param dstAddress - Destination contract address that would receive the interchain message.
     * @param payload - Actual payload for receiver.
     * @param refundAddress - Address used for refundding.
     * @param interchainFuelAddress - Address that would pay for interchain costs.
     * @param params - Custom params for extension.
     */
    event InterchainMsgSent(
        uint16 indexed dstChainID,
        bytes indexed dstAddress,
        bytes payload,
        address refundAddress,
        address interchainFuelAddress,
        bytes params
    );

    event InterchainMsgReceived(
        uint16 indexed srcChainID,
        bytes indexed srcChainAddress,
        uint64 indexed nonce,
        bytes payload
    );

    /**
     * @notice Contoller calls this to send cross-chain requests to Exocore validator set.
     * @param _msg The interchain message sent from client chain Gateway to Exocore validator set for cross-chain communication.
     */
    function sendInterchainMsg(InterchainMsg calldata _msg) external payable;

    /**
     * @notice Only Exocore validator set could indirectly call this through bridge or relayer.
     * @param _msg The interchain message received from Exocore validator set for cross-chain communication.
     */
    function receiveInterchainMsg(uint16 _srcChainID, bytes calldata _srcAddress, uint64 _nonce, InterchainMsg calldata _msg) external;
}