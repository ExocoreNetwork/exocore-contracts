pragma solidity ^0.8.19;

interface IGateway {
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
        uint16  dstChainID;
        bytes  dstAddress;
        bytes payload;
        address payable refundAddress;
        address payable interchainFuelAddress;
        bytes params;
    }

    /**
     * @dev emitted when sending interchain message from Gateway or receiving from Exocore validator set. 
     * @param dstChainID - destination chain ID.
     * @param dstAddress - destination contract address that would receive the interchain message.
     * @param payload - actual payload for receiver.
     * @param refundAddress - address used for refundding.
     * @param interchainFuelAddress - address that would pay for interchain costs.
     * @param params - austom params for extension.
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
     * @notice contoller calls this to send cross-chain requests to Exocore validator set.
     * @param _dstChainId - the destination chain identifier.
     * @param _payload a custom bytes payload to send to the destination contract.
     * @param _refundAddress - if the source transaction is cheaper than the amount of value passed, refund the additional amount to this address.
     * @param _zroPaymentAddress - the address of the ZRO token holder who would pay for the transaction.
     * @param _adapterParams - parameters for custom functionality. e.g. receive airdropped native gas from the relayer on destination.
     */
    function sendInterchainMsg(uint16 _dstChainId, bytes calldata _payload, address payable _refundAddress, address _zroPaymentAddress, bytes memory _adapterParams) external payable;

    /**
     * @notice Only Exocore validator set could indirectly call this through bridge or relayer.
     * @param _srcChainId - the source endpoint identifier.
     * @param _srcAddress - the source sending contract address from the source chain.
     * @param _nonce - the ordered message nonce.
     * @param _payload - the signed payload is the UA bytes has encoded to be sent.
     */
    function receiveInterchainMsg(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload, bytes calldata sig) external;
}