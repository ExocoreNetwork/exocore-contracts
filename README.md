# Exocore Contracts

The Exocore contracts repository contains a set of smart contracts deployed on the target client chains, managed by the Exocore validator set, which facilitate assets deposit and withdrawal, cross-chain communication, and restaking operations for native assets and liquid staking tokens (LSTs), ensuring secure interactions and efficient management of restaked assets.

## Getting Started

* [Documentation](#documentation)
* [Building and Running Tests](#building-and-running-tests)
* [Deployments](#deployments)

## Documentation

### Basics

Our docs site is [here](https://docs.exocore.network/components/smart-contracts). It contains tutorials, explainers, and smart contract documentation. If you'd like to view these docs on github instead, check out [the docs](/docs) repo:

- [Contracts summary](./docs/summary.md)
- [Architecture diagrams](/docs/architecture.svg)
- [LST restaking flow diagrams](/docs/lst-flow.svg)

### Dive

For the latest and most detailed technical documentation, visit [/docs](/docs) directory. If you're an advanced coder, this is the perfect place to get an overview of the contracts before you start exploring the code.

To understand how users interact with these contracts, take a look at our [Tests](./test/).

## Building and Testing

This repository utilizes Foundry. For more information on installation and usage, refer to the [Foundry documentation](https://book.getfoundry.sh/). If you already have Foundry installed, you can build this project and run tests using the following commands:

```
foundryup

git clone --recurse-submodules git@github.com:ExocoreNetwork/exocore-contracts.git && cd exocore-contracts

forge build

forge test
```

### Running localnet tests

We have several tests against the local anvil testnet. To pass these tests, you need to set the environment variable. Refer to `.env.example` for guidance. Once your environment is set up, running `forge script/test` should show these tests passing.

`source .env`

Then run the test like:

`forge script script/1_Prerequisities.s.sol --broadcast -vvvv`

`forge test -vvvv --match-path/--match-path xxxx`

Deposit & Withdraw e2e test:

`forge test -vvvv --match-test test_DepositWithdraw`

### Running Static Analysis

1. Install [solhint](https://github.com/protofire/solhint), then run:

`solhint 'src/contracts/**/*.sol'`

2. Install [slither](https://github.com/crytic/slither), then run:

`slither .`


## Deployments

### Current Testnet Deployment

The current main deployment is our v1.0.0 release. You can view the deployed contract addresses below, or check out the code itself on the [`main`](https://github.com/ExocoreNetwork/exocore-contracts/tree/main) branch.

###### Core

| Name | Proxy | Implementation | Notes |
| -------- | -------- | -------- | -------- |
| [`ClientChainGateway`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/ClientChainGateway.sol) | [`0xe9591d5b1ea9733ad36834cd0bde40ce0028ae33`](https://sepolia.etherscan.io/address/0xe9591d5b1ea9733ad36834cd0bde40ce0028ae33) | [`0xdC51F6d62ce78EfF7c98f3BD59227B4D0785C6ef`](https://sepolia.etherscan.io/address/0xdC51F6d62ce78EfF7c98f3BD59227B4D0785C6ef) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |
| [`ExocoreGateway`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/ExocoreGateway.sol) | [`0xe13Ef2fE9B4bC1A3bBB62Df6bB19d6aD79525036`](https://exoscan.org/address/0xe13Ef2fE9B4bC1A3bBB62Df6bB19d6aD79525036) | [`0xe13Ef2fE9B4bC1A3bBB62Df6bB19d6aD79525036`](https://exoscan.org/address/0xe13Ef2fE9B4bC1A3bBB62Df6bB19d6aD79525036) | Proxy: - |
| [`TokenVault`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/Vault.sol) | [`0x0F4760CCab936a8fb0C9459dba2a739B22059b5f`](https://sepolia.etherscan.io/address/0x0F4760CCab936a8fb0C9459dba2a739B22059b5f) | [`0xF22097E6799DF7D8b25CCeF6E64DA3CB9133012D`](https://sepolia.etherscan.io/address/0xF22097E6799DF7D8b25CCeF6E64DA3CB9133012D) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |
| [`Bootstrap`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/Bootstrap.sol) | [`0x53E91EB5105ec8C1c22055F790616cB8F82c664e`](https://sepolia.etherscan.io/address/0x53E91EB5105ec8C1c22055F790616cB8F82c664e) | [`0x417CaBa1E4a63D1202dCc6E19F7c3eC79b31EC45`](https://sepolia.etherscan.io/address/0x417CaBa1E4a63D1202dCc6E19F7c3eC79b31EC45) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |
| [`LzEndpoint`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/Bootstrap.sol) | [`0x6EDCE65403992e310A62460808c4b910D972f10f`](https://sepolia.etherscan.io/address/0x6EDCE65403992e310A62460808c4b910D972f10f) | [`0x6EDCE65403992e310A62460808c4b910D972f10f`](https://sepolia.etherscan.io/address/0x6EDCE65403992e310A62460808c4b910D972f10f) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |
