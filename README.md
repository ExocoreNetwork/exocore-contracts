# Exocore Contracts

## Overview 

**Exocore contracts refer to the set of smart contracts deployed on target client chain and controlled by Exocore validator set**

Generally Exocore contracts have these components:

- `Gateway`: The cross-chain portal responsible for verifying the signed commands from Exocore core layer, and calling specific functions of `Controller` . It should also be the entry point where stakers request to interact with the Exocore core layer from client chain by emitting specific events.
- `Controller` : The controller of `Vault` contract to operate on `Vault` .
- `Vault` : Stakers’ assets would be deposited to this contract, and it should manage the deposit and withdraw for stakers. Most of its operations should be strictly restricted to its `Controller` .

## Documentation

https://www.notion.so/Client-Chain-Smart-Contracts-Workflow-8356cec4e30f4ea8b26ddb451102ab7e

