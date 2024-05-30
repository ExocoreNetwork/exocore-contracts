# Exocore Contracts

Exocore is a set of smart contracts deployed on the target client chain, controlled by the Exocore validator set. This repository contains the core Exocore contracts, which support assets including native assets and various liquid staking tokens (LSTs). Users can use these contracts to deposit and withdraw assets, as well as delegate them to operators providing services to AVSs.

## Getting Started

* [Documentation](#documentation)
* [Building and Running Tests](#building-and-running-tests)
* [Deployments](#deployments)

## Documentation

### Basics

Our docs site is [here](https://docs.exocore.network/components/smart-contracts). It contains tutorials, explainers, and smart contract documentation. If you'd like to view these docs on github instead, check out [the docs](/docs) in the docs repo:

- [Contracts summary](./docs/summary.md)
- [Architecture diagrams](/docs/architecture.svg)
- [LST restaking flow diagrams](/docs/lst-flow.svg)

### Dive

For the latest and most detailed technical documentation, visit our [/docs](/docs) directory. If you're an advanced coder, this is the perfect place to get an overview of the contracts before you start exploring the code.

To understand how users interact with these contracts, take a look at our [Integration Tests](./test/).

## Building and Testing

This repository utilizes Foundry. For more information on installation and usage, refer to the [Foundry documentation](https://book.getfoundry.sh/). If you already have Foundry installed, you can build this project and run tests using the following commands:

```
foundryup

git clone --recurse-submodules git@github.com:ExocoreNetwork/exocore-contracts.git && cd exocore-contracts

forge build
forge test
```

### Running localnet tests

We have several tests against the local anvil testnet. To pass these tests, you need to set the `RPC_main` environment variable. Refer to `.env.example` for guidance. Once your environment is set up, running `forge test` should show these tests passing.

`source .env`

Then run the tests:

`forge test --fork-url [RPC_URL]`

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
| [`ClientChainGateway`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/ClientChainGateway.sol) | [`0x...`](https://etherscan.io/address/0x...) | [`0x...`](https://etherscan.io/address/0x...) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |
| [`ExocoreGateway`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/ExocoreGateway.sol) | [`0x...`](https://etherscan.io/address/0x...) | [`0x...`](https://etherscan.io/address/0x...) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |
| [`TokenVault`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/Vault.sol) | [`0x...`](https://etherscan.io/address/0x...) | [`0x...`](https://etherscan.io/address/0x...) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |
| [`Bootstrap`](https://github.com/ExocoreNetwork/exocore-contracts/blob/main/src/contracts/core/Bootstrap.sol) | [`0x...`](https://etherscan.io/address/0x...) | [`0x...`](https://etherscan.io/address/0x...) | Proxy: [`TUP@4.7.1`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.1/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) |

## Coverage

We use the [solidity-coverage](https://github.com/sc-forks/solidity-coverage) package to generate our coverage reports. You can find the coverage report on [coveralls](https://). Alternatively, you can generate it locally by running:

```sh
$ npm run coverage
```

The full report can be viewed by opening the `coverage/index.html` file in a browser.