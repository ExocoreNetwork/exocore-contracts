pragma solidity >=0.8.17;

/// @dev The BLS contract's address.
address constant BLS_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000809;

/// @dev The BLS contract's instance.
IBLS constant BLS_CONTRACT = IBLS(
    BLS_PRECOMPILE_ADDRESS
);

/// @author Exocore Team
/// @title BLS Precompile Contract
/// @dev The interface through which solidity contracts will interact with BLS
/// @custom:address 0x0000000000000000000000000000000000000809
interface IBLS {
    /// @dev verify BLS aggregated signature against aggregated public key
    /// @param msg_ the message that is signed
    /// @param signature the aggregated signature
    /// @param pubKey the aggregated public key
    function verify(
        bytes32 msg_,
        bytes calldata signature,
        bytes calldata pubKey
    ) external pure returns (bool valid);

    /// @dev verify BLS aggregated signature against public keys
    /// @param msg_ the message that is signed
    /// @param signature the aggregated signature
    /// @param pubKeys the aggregated public key
    function fastAggregateVerify(
        bytes32 msg_,
        bytes calldata signature,
        bytes[] calldata pubKeys
    ) external pure returns (bool valid);
}

