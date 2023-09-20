# Exocore Client Chain Smart Contracts Design 

## Overview

Exocore Client chain smart contracts refer to a set smart contracts that are deployed on multiple chains(evm-compatible chains for current version), and
provided for Exocore users(mainly stakers) to interact with Exocore system from specific client chain. And most of its administrative functionalities are
only acccessble for Exocore validator set via valid TSS signature forwarded by some third-party bridge(Layerzero) or Exocore itself.

As the two main functionalities of client chain smart contracts include:

1. Take user funds into custody when users ask to enter Exocore system, update user balance periodically and deal with withdrawal request of user
based on withdrawable balance.
2. Forward user request from client chain side to Exocore validator set, as well as receive response from Exocore validator set to update state or
execute some operations.

We have these components included in Exocore client chain smart contracts architecture:

1. `Gateway`: This is the entry point where client chain users make request to Exocore validator set, as well as the end point that receives cross-chain
messages from Exocore validator set.
2. `Vault`: This is where user funds are taken into custody and managed. Within `Vault`, user balance is updated periodically by Exocore validator set through cross-chain message to reveal user's real position(after slashing, rewarding and other impact). Users can withdraw from `Vault` based on grant from Exocore validator set. Every specific asset should have standalone `Vault`.
3. `Controller`: The controller that is responsible for managing multiple `Vault`s. It should be the entry point for operations on `Vault`, as well as the entry point for user's interactions with Exocore validator set.

## `Gateway`

Similar to LayerZero `endpoint`, `Gateway` is mainly responsible for sending cross-chain messages and receiving cross-chain messages. The validity of cross-chain messages are guaranteed by LayerZero oracle and relayer if integrated with LayerZero protocol, otherwise `Gateway` itself should validate the cross-chain messages.

`Gateway` is also the router that forwards messages from Exocore validator set to its destination contract to be handled. Curretly this mainly refers to forwarding response from Exocore validator set to `Controller` to execute the messages.

```solidity
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

    /**
     * @notice Contoller calls this to send cross-chain requests to Exocore validator set.
     * @param msg The interchain message sent from client chain Gateway to Exocore validator set for cross-chain communication.
     */
    function sendInterchainMsg(InterchainMsg calldata msg) external payable;

    /**
     * @notice Only Exocore validator set could indirectly call this through bridge or relayer.
     * @param msg The interchain message received from Exocore validator set for cross-chain communication.
     */
    function receiveInterchainMsg(InterchainMsg calldata msg) external payable;
}
```

