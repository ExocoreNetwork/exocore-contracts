# Exocore Contracts

## Overview 

**Exocore contracts refer to the set of smart contracts deployed on target client chain and controlled by Exocore validator set**

Generally Exocore contracts have these components:

- `Gateway`: The cross-chain portal responsible for verifying the signed commands from Exocore core layer, and calling specific functions of `Controller` . It should also be the entry point where stakers request to interact with the Exocore core layer from client chain by emitting specific events.
- `Controller` : The controller of `Vault` contract to operate on `Vault` .
- `Vault` : Stakers’ assets would be deposited to this contract, and it should manage the deposit and withdraw for stakers. Most of its operations should be strictly restricted to its `Controller` .

## Documentation

1. workflow design: https://www.notion.so/Client-Chain-Smart-Contracts-Workflow-8356cec4e30f4ea8b26ddb451102ab7e
2. design principles: https://www.notion.so/Client-Chain-Contracts-Design-8ab37ee6a31444629fb2839a84f8422d?pvs=4
3. implementation specifications and architecture choice notes: https://www.notion.so/Contract-Implementation-Notes-f9467324c8f74f268f56f6d5e5a9eecf?pvs=4
4. cross-chain message serialization proposal: https://www.notion.so/Cross-Chain-Message-Serialization-Proposal-f40ff04a94524d5298cfa866904baa14?pvs=4
   
## Test

### e2e test

1. Deposit
   ```sh
   forge test -vvvv --match-test test_DepositWithdraw
   ```


