pragma solidity ^0.8.19;

contract ExocoreBtcGatewayStorage {

    mapping(address token => bool whitelisted) public isWhitelistedToken;
    mapping(uint32 eid => mapping(bytes sender => uint64 nonce)) public inboundBytesNonce;
    address payable public exocoreValidatorSetAddress;

    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);

    modifier isTokenWhitelisted(address token) {
        require(isWhitelistedToken[token], "GatewayStorage: token is not whitelisted");
        _;
    }

    modifier isValidAmount(uint256 amount) {
        require(amount > 0, "GatewayStorage: amount should be greater than zero");
        _;
    }

    function _verifyAndUpdateBytesNonce(uint32 srcChainId, bytes memory srcAddress, uint64 nonce) internal {
        uint64 expectedNonce = inboundBytesNonce[srcChainId][srcAddress] + 1;
        if (nonce != expectedNonce) {
            revert UnexpectedInboundNonce(expectedNonce, nonce);
        }
        inboundBytesNonce[srcChainId][srcAddress] = nonce;
    }

    uint256[40] private __gap;

}
