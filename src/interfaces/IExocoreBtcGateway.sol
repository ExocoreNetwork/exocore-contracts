// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IExocoreBtcGateway {

    struct TxInfo {
        bool processed;
        uint256 timestamp;
    }

    struct InterchainMsg {
        uint32 srcChainID;
        uint32 dstChainID;
        bytes srcAddress;
        bytes dstAddress;
        address token; // btc virtual token
        uint256 amount; //btc deposit amount
        uint64 nonce;
        bytes txTag; //btc lowercase(txid-vout)
        bytes payload;
    }

    error InvalidSignature();

    event MessageProcessed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event MessageFailed(uint32 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload, bytes _reason);

}
