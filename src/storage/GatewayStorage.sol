pragma solidity ^0.8.19;

contract GatewayStorage {

    enum Action {
        REQUEST_DEPOSIT,
        REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE,
        REQUEST_WITHDRAW_REWARD_FROM_EXOCORE,
        REQUEST_DELEGATE_TO,
        REQUEST_UNDELEGATE_FROM,
        REQUEST_DEPOSIT_THEN_DELEGATE_TO,
        REQUEST_MARK_BOOTSTRAP,
        REQUEST_ADD_WHITELIST_TOKENS,
        RESPOND
    }

    mapping(Action => bytes4) internal _whiteListFunctionSelectors;
    address payable public exocoreValidatorSetAddress;

    mapping(uint32 eid => mapping(bytes32 sender => uint64 nonce)) public inboundNonce;

    event MessageSent(Action indexed act, bytes32 packetId, uint64 nonce, uint256 nativeFee);

    error UnsupportedRequest(Action act);
    error UnexpectedSourceChain(uint32 unexpectedSrcEndpointId);
    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);

    uint256[40] private __gap;

    function _verifyAndUpdateNonce(uint32 srcChainId, bytes32 srcAddress, uint64 nonce) internal {
        uint64 expectedNonce = inboundNonce[srcChainId][srcAddress] + 1;
        if (nonce != expectedNonce) {
            revert UnexpectedInboundNonce(expectedNonce, nonce);
        }
        inboundNonce[srcChainId][srcAddress] = nonce;
    }

}
