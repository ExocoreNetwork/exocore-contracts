pragma solidity ^0.8.19;

import "../../src/interfaces/precompiles/IBLS.sol";

contract BLS12381Caller {
    bytes public aggregatedPubkeys;
    bytes public aggregatedSigs;
    bytes32 public expectedMsg = keccak256(bytes("this is a test message"));
    bool public verifyValid;
    bool public aggregateVerifyValid;

    function aggregatePubkeys(bytes[] calldata pubkeys) external {
        for (uint8 i; i < pubkeys.length; i++) {
            require(pubkeys[i].length == 48, "invalid public key length");
        }
        (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.aggregatePubkeys.selector,
            pubkeys
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        aggregatedPubkeys = abi.decode(data, (bytes));
    } 

    function aggregatePubkeysPure(bytes[] calldata pubkeys) external view returns (bytes memory aggPubkey) {
        for (uint8 i; i < pubkeys.length; i++) {
            require(pubkeys[i].length == 48, "invalid public key length");
        }
        (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.aggregatePubkeys.selector,
            pubkeys
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        aggPubkey = abi.decode(data, (bytes));
    } 

    function generatePrivateKey() external view returns(bytes memory privkey) {
        (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.generatePrivateKey.selector
        ));
        require(success, "failed to call bls precompile");
        privkey = abi.decode(data, (bytes));
    }

    function aggregateSigs(bytes[] calldata sigs) external {
        for (uint8 i; i < sigs.length; i++) {
            require(sigs[i].length == 96, "invalid signature length");
        }
        (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.aggregateSignatures.selector,
            sigs
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        aggregatedSigs = abi.decode(data, (bytes));
    }   

    function verify(bytes32 msg_, bytes calldata sig, bytes calldata pubkey) external {
        (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.verify.selector,
            msg_,
            sig,
            pubkey
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        verifyValid = abi.decode(data, (bool));
    }

    function fastAggregateVerify(bytes32 msg_, bytes calldata sig, bytes[] calldata pubkeys) external {
        (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.fastAggregateVerify.selector,
            msg_,
            sig,
            pubkeys
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        aggregateVerifyValid = abi.decode(data, (bool));
    }

    function fastAggregateVerifyPure(bytes32 msg_, bytes calldata sig, bytes[] calldata pubkeys) external view returns(bool valid) {
        (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.fastAggregateVerify.selector,
            msg_,
            sig,
            pubkeys
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        valid = abi.decode(data, (bool));
    }
}