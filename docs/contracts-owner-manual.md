# Contract Owner's Manual

Currently almost all contracts are ownable contracts including `Bootstrap`, `ClientChainGateway`, `Vault`, `ExocoreGateway`. The owner of these contracts is a privileged account in many aspects including upgrading contract by changing implementation, registering some client chain to Exocore before enabling restaking from that client chain, adding token info to whitelist and even pausing/unpausing contracts in case of emergencies.

## Owner Only Functionalities

## `pause`/`unpause`

In case of emergencies where some unexpected errors happened to the protocol, contract owner could pause the contract to disable all user-facing functions and re-enable these functions after successfully recovering from emergencies. Currently pauseable contracts include `Bootstrap`, `ClientChainGateway`, `ExocoreGateway`. For `Vault` and `ExoCapsule`, as all the functions are limited to be called by their management contract(`ClientChainGateway`, `Bootstrap`), their functionalities are also paused when their management contract get paused.

## upgrade to new implementation

Most contracts including `Bootstrap`, `ClientChainGateway`, `ExocoreGateway`, `Vault` and `ExoCapsule` are upgradeable. For `Bootstrap`, `ClientChainGateway` and `ExocoreGateway`, they are upgradeable through `ProxyAdmin` contract, so the owner of `ProxyAdmin` could upgrade these contracts by changing implementation contract.
While for `Vault` and `ExoCapsule`, they are deployed with upgradeable beacon proxy, so only `upgradeableBeacon` could access the upgrading functionalities of these contracts, that is to say only the owner of `upgradeableBeacon` could upgrade these contracts by changing implementation contract. Notice as all `Vault`s are deployed with upgradeable beacon proxy and all these proxies point to the same `upgradeableBeacon` contract, when the owner change implementation contract stored in `upgradeableBeacon`, all `Vault`s get upgraded to the same new version of contract, and same case for `ExoCapsule`.

## register client chain

After all contracts are deployed, before the protocol starts to work, there are a few works left to be done by contract owner to enable restaking. One of the most important tasks is to registering the client chain id and meta info to Exocore to mark this client chain as valid. This is done by the contract caller calling `ExocoreGateway.registerOrUpdateClientChain` to write `clientChainId`, `addressLength`, `name`, `signatureType` and other meta data to Exocore native module to finish registration. This operation would also call `ExocoreGateway.setPeer` to enable LayerZero messaging by setting remote `ClientChainGateway` as trusted peer to send/receive messages. After finishing registration, contract owner could call `ExocoreGateway.registerOrUpdateClientChain` again to update the meta data and set new peer, or contract owner could solely call `ExocoreGateway.setPeer` to change the address of remote peer contract.

## add tokens to whitelist

Another important task before restaking being activated is to adding tokens to whitelist to mark them as stake-able on both Exocore and client chain. This is done by contract owner calling `ExocoreGateway.addWhitelistTokens` to write token addresses, decimals, TVL limits and other metadata to Exocore, as well as sending a cross-chain message through layerzero to client chain to add these token addresses to the whitelist of `ClientChainGateway`. 

Notice: contract owner must make sure the token data is correct like address, decimals and TVL limit, more importantly contract owner must ensure that for the same index, the data in different arrays like `tokens`, `decimals`, `tvlLimits` must point to the same token to be composed as complete token data.

## upgrade the meta data of whitelisted tokens 

After adding tokens to whitelist, contract owner could call `ExocoreGateway.updateWhitelistedTokens` to update the meta data of already whitelisted tokens, and this function would not send a cross-chain message to client chain since the whitelist of `ClientChainGateway` only stores the token addresses.