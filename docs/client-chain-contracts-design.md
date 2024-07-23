# Client Chain Contracts Design

## Overview

Exocore Client chain smart contracts refer to a set smart contracts that are deployed on multiple chains (EVM-compatible chains for current version), and provided for Exocore users (mainly stakers) to interact with Exocore system from specific client chains. The administrative functionalities of these contracts are via their owner, which ideally should be a multi-sig.

The two main functionalities of client chain smart contracts include:

1. Take user funds into custody when users ask to enter Exocore system, update user balance periodically and deal with withdrawal request of user based on withdrawable balance.
2. Forward user request from client chain side to Exocore validator set, as well as receive response from Exocore validator set to update state or execute some operations.

We have these components included in Exocore client chain smart contracts architecture:

1. `ClientChainGateway`: This is the entry point where client chain users make request to Exocore validator set, as well as the end point that receives cross-chain messages from Exocore validator set.
2. `Vault`: This is where user funds are taken into custody and managed. Within `Vault`, user balance is updated periodically by Exocore validator set through cross-chain message to reveal user’s real position (after slashing, rewarding and other impact). Users can withdraw from `Vault` based on grant from the gateway. Every specific asset should have standalone `Vault`.
3. `LSTRestakingController`: The controller is responsible for managing multiple `Vault`s. It should be the entry point for operations on `Vault`, as well as the entry point for user’s interactions with the gateway. It is inherited / implemented by the `Gateway`.

## Upgrade

Upgradeable contracts rely on three components: storage contract, logic contract, proxy contract. All upgradeable contracts architecture utilizes the fact that inside a proxy contract, if we `delegatecall` the logic contract, the code of the logic contract would be loaded in the context of the proxy contract. Therefore, the proxy contract actually forwards the call to a logic contract but reads and writes the proxy’s own state variables. That way, a proxy contract can inherit the old state (and even add state variables) even if the logic contract is replaced.

After the upgrade, the new logic contract (with the new implementation) must align the storage with the previous storage layout by extending it. It means that no state variables should be removed, and the type as well as the order of state variable should remain the same. All future versions of the logic contract must inherit the same storage contract to make the storage layout compatible after upgrade. Afterwards, by replacing the old logic contract address with the address of new logic contract, we can upgrade a contract without violating its storage.

In this architecture, proxy contracts do not inherit the storage contract and are kept as stateless as possible.

For the purpose of allowing adding state variables to proxy contract, we need to retain some unused slots in the end of storage contract so that we can add new state variables and override the unused slots.

```solidity
contract GatewayStorage {
......
/**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[44] private __gap;
}
```

Besides all of these techniques, there are other details that we need to handle when designing upgradeable contracts, like function signature collision and forbidding initializing state variables in `constructor` and so on. Openzeppelin’s `TransparentUpgradeableProxy` and upgradeable implementation of token standards like `ERC20Upgradeable` handle these details properly.

1. `TransparentUpgradeableProxy` would store the meta state variables like logic contract address to random slots to avoid state variable storage layout collision.
2. [OpenZeppelin/openzeppelin-contracts-upgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable) follows the upgradeable design through the following:

> constructors are replaced by initializer functions, state variables are initialized in initializer functions, and we additionally check for storage incompatibilities across minor versions.

In most of the cases, we can not directly use implementations linked above and need to implement our own upgradeable contracts. When we write our own upgradeable smart contracts, we must follow these principles:

1. Our upgradeable contracts should always inherit from OZ's upgradeable contracts.
2. Do not assign an initial value to state variables when declaring them except `immutable` and `constant`.
3. Do not assign initial value to state variables in `constructor` except `immutable` .
4. Replace `constructor` with openzeppelin’s `initializer` modifier.
5. Disable initializers in `constructor` to prevent anyone else directly initialize the contract without calling the proxy.

Upgradable contract actually means the logic contract in our upgradeable contract architecture. So every upgradeable contract should be put behind a proxy contract.

Most commonly, community uses openzeppelin’s `[TransparentUpgradeableProxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#TransparentUpgradeableProxy)` implementation. Take EigenLayer contracts for example:

```solidity
/**
         * First, deploy upgradeable proxy contracts that **will point** to the implementations. Since the implementation contracts are
         * not yet deployed, we give these proxies an empty contract as the initial implementation, to act as if they have no code.
         */
        emptyContract = new EmptyContract();
        delegation = DelegationManager(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );
        .....

        // Second, deploy the *implementation* contracts, using the *proxy contracts* as inputs
        DelegationManager delegationImplementation = new DelegationManager(strategyManager, slasher);
        .....

        // Third, upgrade the proxy contracts to use the correct implementation contracts and initialize them.
        eigenLayerProxyAdmin.upgradeAndCall(
            TransparentUpgradeableProxy(payable(address(delegation))),
            address(delegationImplementation),
            abi.encodeWithSelector(
                DelegationManager.initialize.selector,
                eigenLayerReputedMultisig,
                eigenLayerPauserReg,
                0/*initialPausedStatus*/
            )
        );
        .....
```

It follow these steps:

1. First, deploy upgradeable proxy contracts that will point to the implementations. Since the implementation contracts are not yet deployed, we give these proxies an empty contract as the initial implementation, to act as if they have no code.
2. Second, deploy the implementation contracts, using the proxy contracts as inputs.
3. Third, upgrade the proxy contracts to use the correct implementation contracts and initialize them.

On the other hand, openzeppelin’s doc suggests using `[UUPSUpgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable)` while `[TransparentUpgradeableProxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#TransparentUpgradeableProxy)` being the most popular upgradeable proxy. We could explore `[UUPSUpgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable)` while we reserve the plan of using `[TransparentUpgradeableProxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#TransparentUpgradeableProxy)` .

For more details please refer to these docs:

[Proxy Upgrade Pattern - OpenZeppelin Docs](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies#the-constructor-caveat)

[Writing Upgradeable Contracts - OpenZeppelin Docs](https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable)

## `Gateway`

Similar to LayerZero `endpoint`, `ClientChainGateway` is mainly responsible for sending cross-chain messages and receiving cross-chain messages. The validity of cross-chain messages are guaranteed by LayerZero oracle and relayer if integrated with LayerZero protocol, otherwise `Gateway` itself should validate the cross-chain messages.

Eventually, Exocore validator set should be the owner of `ClientChainGateway` so that it can update some state variables or even upgrade it in the future. In the early stages, a more controlled way to upgrade is needed, for example, a multi-sig.

We have made `ClientChainGateway` contract upgradable so that the state can be retained while adding or removing some features in the future.

```solidity
contract BaseRestakingController {
    /// @dev Sends a message to Exocore.
    /// @param action The action to be performed.
    /// @param actionArgs The encodePacked arguments for the action.
    function _sendMsgToExocore(Action action, bytes memory actionArgs);

    /// @inheritdoc OAppReceiverUpgradeable
    function _lzReceive(Origin calldata _origin, bytes calldata payload);
}
```

### `_sendMsgToExocore`

This internal function is used to send a message, over LayerZero, from the client chain to the Exocore chain. It encodes the action to perform, along with its payload, and forwards the packed data. The fees for this cross-chain message is provided by the calling address.

### `_lzReceive`

This internal function is called via LayerZero upon the receipt of a cross-chain message. In the context of the `ClientChainGateway`, it is used to handle the response provided by the Exocore chain against an outgoing message. For example, if a withdraw request is initiated by a user, and sent by the `ClientChainGateway` to Exocore, a response is received indicating whether the withdrawal is valid. Based on this validity, `ClientChainGateway` marks the funds available for the user to claim.

## `Vault`

Every whitelisted native token on the client chain for Exocore has a standalone `Vault` used for user funds custody. Each `Vault` contract takes into custody the user's assets and stores them on their behalf. A user can enter the system by providing approval to the `Vault` contract and then depositing in it through the `ClientChainGateway`. Similarly, a user can exit the system by undelegating and withdrawing their assets and claiming them from the vault.

The assets in a `Vault` include the principal deposited as well as any rewards that may have accrued to the staker and any reductions for slashing. While each `Vault` contract stores some data, Exocore is the single source of truth for the accurate withdrawable, deposited and staked balances.

```solidity
interface IVault {

    /// @notice Withdraws a specified amount from the vault.
    /// @param withdrawer The address initiating the withdrawal.
    /// @param recipient The address receiving the withdrawn amount.
    /// @param amount The amount to be withdrawn.
    function withdraw(address withdrawer, address recipient, uint256 amount) external;

    /// @notice Deposits a specified amount into the vault.
    /// @param depositor The address initiating the deposit.
    /// @param amount The amount to be deposited.
    function deposit(address depositor, uint256 amount) external payable;

    /// @notice Updates the principal balance for a user.
    /// @param user The address of the user whose principal balance is being updated.
    /// @param lastlyUpdatedPrincipalBalance The new principal balance for the user.
    function updatePrincipalBalance(address user, uint256 lastlyUpdatedPrincipalBalance) external;

    /// @notice Updates the reward balance for a user.
    /// @param user The address of the user whose reward balance is being updated.
    /// @param lastlyUpdatedRewardBalance The new reward balance for the user.
    function updateRewardBalance(address user, uint256 lastlyUpdatedRewardBalance) external;

    /// @notice Updates the withdrawable balance for a user.
    /// @param user The address of the user whose withdrawable balance is being updated.
    /// @param unlockPrincipalAmount The amount of principal to be unlocked.
    /// @param unlockRewardAmount The amount of reward to be unlocked.
    function updateWithdrawableBalance(address user, uint256 unlockPrincipalAmount, uint256 unlockRewardAmount)
        external;

    /// @notice Returns the address of the underlying token.
    /// @return The address of the underlying token.
    function getUnderlyingToken() external returns (address);

}
```

`principalBalance` refers to the principal that the user deposits into the `ClientChainGateway`. It is separated from the rewards earned by the users, since such rewards could be distributed on the Exocore chain or on another client chain while the user principal is taken in custody on this chain. Besides, we assume that the principal balance can only be influenced during slashing and that it is not transferable to any other address. In other words, the principal balance to be withdrawn can never be greater than the originally deposited principal balance.

### `deposit`

The implementation of this function transfers user funds into `Vault` address and updates the user's principal balance correspondingly.

This function is only accessible for `ClientChainGateway` so that this function could only work as part of the process of the whole deposit workflow and ensure the whole workflow is controlled by `ClientChainGateway`.

Whenever a `deposit` request is received by the `ClientChainGateway`, it first deposits the amount into the `Vault`. Then, it forwards the transaction to Exocore, where it is appropriately processed, in line with the `checks-effects-interactions` pattern.

### `withdraw`

This function allows a user to claim their withdrawable assets. The quantity of the withdrawable assets is set by the `ClientChainGateway` in response to a withdraw request, after receiving a response from Exocore.

## `LSTRestakingController`

`LSTRestakingController` is the manager of all `Vaults`, as well as the entry point where users call to interact with Exocore system.

Ideally, the Exocore validator set should own `LSTRestakingController` so that upgrades can be made trustlessly.

```solidity
interface IBaseRestakingController {

    /// @notice Delegates a specified amount of tokens to a given operator.
    /// @param operator The address of the operator to delegate tokens to.
    /// @param token The address of the token to be delegated.
    /// @param amount The amount of tokens to delegate.
    function delegateTo(string calldata operator, address token, uint256 amount) external payable;

    /// @notice Undelegates a specified amount of tokens from a given operator.
    /// @param operator The address of the operator to undelegate tokens from.
    /// @param token The address of the token to be undelegated.
    /// @param amount The amount of tokens to undelegate.
    function undelegateFrom(string calldata operator, address token, uint256 amount) external payable;

    /// @notice Client chain users call to claim their unlocked assets from the vault.
    /// @dev This function assumes that the claimable assets should have been unlocked before calling this.
    /// @dev This function does not ask for grant from Exocore validator set.
    /// @param token The address of specific token that the user wants to claim from the vault.
    /// @param amount The amount of @param token that the user wants to claim from the vault.
    /// @param recipient The destination address that the assets would be transfered to.
    function claim(address token, uint256 amount, address recipient) external;

}

interface ILSTRestakingController is IBaseRestakingController {

    /// @notice Deposits tokens into the Exocore system for further operations like delegation and staking.
    /// @dev This function locks the specified amount of tokens into a vault and informs the Exocore validator set.
    /// Deposit is always considered successful on the Exocore chain side.
    /// @param token The address of the specific token that the user wants to deposit.
    /// @param amount The amount of the token that the user wants to deposit.
    function deposit(address token, uint256 amount) external payable;

    /// @notice Requests withdrawal of the principal amount from Exocore to the client chain.
    /// @dev This function requests withdrawal approval from the Exocore validator set. If approved, the assets are
    /// unlocked and can be claimed by the user. Otherwise, they remain locked.
    /// @param token The address of the specific token that the user wants to withdraw from Exocore.
    /// @param principalAmount The principal amount of assets the user deposited into Exocore for delegation and
    /// staking.
    function withdrawPrincipalFromExocore(address token, uint256 principalAmount) external payable;

    /// @notice Withdraws reward tokens from Exocore.
    /// @param token The address of the specific token that the user wants to withdraw as a reward.
    /// @param rewardAmount The amount of reward tokens that the user wants to withdraw.
    function withdrawRewardFromExocore(address token, uint256 rewardAmount) external payable;

    /// @notice Deposits tokens and then delegates them to a specific node operator.
    /// @dev This function locks the specified amount of tokens into a vault, informs the Exocore validator set, and
    /// delegates the tokens to the specified node operator.
    /// Delegation can fail if the node operator is not registered in Exocore.
    /// @param token The address of the specific token that the user wants to deposit and delegate.
    /// @param amount The amount of the token that the user wants to deposit and delegate.
    /// @param operator The address of a registered node operator that the user wants to delegate to.
    function depositThenDelegateTo(address token, uint256 amount, string calldata operator) external payable;

}
```

### `deposit` into the `ILSTRestakingController`

See [`deposit`](#deposit).

Once the assets have been deposited into the `Vault`, the `ClientChainGateway` sends a cross-chain message to Exocore, which is obviously asynchronous. Upon receiving the message, Exocore will take into account the deposit, and must respond that the message succeeded. This is because our design requires that deposits can never fail.

### `delegateTo`

This function controls the delegation workflow originating from the client chain. It requires that the caller has previously deposited enough tokens into the system, failing which, the transaction will fail.

The delegation workflow is also separated into two transactions:

1. Transaction from the user: call `ClientChainGateway.sendInterchainMsg` to send delegate request to Exocore chain.
2. Response from Exocore: call `ClientChainGateway.receiveInterchainMsg` to inform whether the delegation is successful or not.

Since the `ClientChainGateway` by itself does not store enough information to check whether a delegation will be successful, this method must not make any state alterations to the balance.

### `undelegateFrom`

This function is the reverse of [`delegatTo`](#delegateto), except that it requires an unbonding period before the undelegation is released for withdrawal. The unbonding period is determined by Exocore on the basis of all of the AVSs in which the operator was participating at the time of undelegation.

### `withdrawPrincipalFromExocore`

This function is aimed for user withdrawing principal from Exocore chain to client chain. This involves the correct accounting on Exocore chain as well as the correct update of user’s `principalBalance` and claimable balance. If this process is successful, user should be able to claim the corresponding assets on client chain to destination address.

The principal withdrawal workflow is also separated into two trasactions:

1. Transaction from the user: call `ClientChainGateway.sendInterchainMsg` to send principal withdrawal request to Exocore chain.
2. Response from Exocore: call `ClientChainGateway.receiveInterchainMsg` to receive the response from Exocore chain, and call `unlock` to update user’s `principalBalance` and claimable balance. If response indicates failure, no user balance should be modified.

The withdrawable amount of principal is defined as follows:

1. The asset is not staked (delegated) on any operators.
2. The asset is not frozen/slashed.
3. The asset is not in unbonding state.

### `claim`

This function is aimed for user claiming the unlocked amount of principal. Before claiming, user must make sure that thre is enogh principal unlocked by calling `withdrawPrincipalFromExocore`. The implementaion of this function should check against user’s claimable balance and transfer tokens to the destination address that the user specified.

### `withdrawRewardFromExocore`

TBD

### `depositThenDelegateTo`

It is an ease-of-use feature to allow deposit and then delegation in one transaction. It has the same assumptions as the underlying two features.
