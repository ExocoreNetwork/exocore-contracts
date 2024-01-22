pragma solidity ^0.8.19;

import "../../src/interfaces/precompiles/IBLS.sol";

contract BLS12381Caller2 {
    bytes public aggregatedPubkeys;
    bytes public aggregatedSigs;
    bytes32 public expectedMsg = keccak256(bytes("this is a test message"));
    bool public verifyValid;
    bool public aggregateVerifyValid;

    function aggregatePubkeys(bytes[] calldata pubkeys) external {
        bytes memory newPubkey;
        for (uint8 i; i < pubkeys.length; i++) {
            require(pubkeys[i].length == 48, "invalid public key length");
            if (i == uint8(0)) {
                newPubkey = pubkeys[0];
            } else {
                (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
                    BLS_CONTRACT.addTwoPubkeys.selector,
                    newPubkey,
                    pubkeys[i]
                ));
                require(success, "failed to call bls precompile");
                require(data.length != 0, "empty return data");
                newPubkey = abi.decode(data, (bytes));
            }
        }
        aggregatedPubkeys = newPubkey;
    } 

    function aggregatePubkeysPure(bytes[] calldata pubkeys) external view returns(bytes memory) {
        bytes memory newPubkey;
        for (uint8 i; i < pubkeys.length; i++) {
            require(pubkeys[i].length == 48, "invalid public key length");
            if (i == uint8(0)) {
                newPubkey = pubkeys[0];
            } else {
                (bool success, bytes memory data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
                    BLS_CONTRACT.addTwoPubkeys.selector,
                    newPubkey,
                    pubkeys[i]
                ));
                require(success, "failed to call bls precompile");
                require(data.length != 0, "empty return data");
                newPubkey = abi.decode(data, (bytes));
            }
        }
        return newPubkey;
    }

    function fastAggregateVerify(bytes32 msg_, bytes calldata sig, bytes[] calldata pubkeys) external {
        bytes memory newPubkey;
        bool success;
        bytes memory data;
        for (uint8 i; i < pubkeys.length; i++) {
            require(pubkeys[i].length == 48, "invalid public key length");
            if (i == uint8(0)) {
                newPubkey = pubkeys[0];
            } else {
                (success, data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
                    BLS_CONTRACT.addTwoPubkeys.selector,
                    newPubkey,
                    pubkeys[i]
                ));
                require(success, "failed to call bls precompile");
                require(data.length != 0, "empty return data");
                newPubkey = abi.decode(data, (bytes));
            }
        }
        (success, data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.verify.selector,
            msg_,
            sig,
            newPubkey
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        aggregateVerifyValid = abi.decode(data, (bool));
    }

    function fastAggregateVerifyPure(bytes32 msg_, bytes calldata sig, bytes[] calldata pubkeys) external view returns(bool valid) {
        bytes memory newPubkey;
        bool success;
        bytes memory data;
        for (uint8 i; i < pubkeys.length; i++) {
            require(pubkeys[i].length == 48, "invalid public key length");
            if (i == uint8(0)) {
                newPubkey = pubkeys[0];
            } else {
                (success, data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
                    BLS_CONTRACT.addTwoPubkeys.selector,
                    newPubkey,
                    pubkeys[i]
                ));
                require(success, "failed to call bls precompile");
                require(data.length != 0, "empty return data");
                newPubkey = abi.decode(data, (bytes));
            }
        }
        (success, data) = BLS_PRECOMPILE_ADDRESS.staticcall(abi.encodeWithSelector(
            BLS_CONTRACT.verify.selector,
            msg_,
            sig,
            newPubkey
        ));
        require(success, "failed to call bls precompile");
        require(data.length != 0, "empty return data");
        valid = abi.decode(data, (bool));
    }
}