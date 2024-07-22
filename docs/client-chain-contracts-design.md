# Client Chain Contracts Design

# Exocore Client Chain Smart Contracts Design

## Overview

Exocore Client chain smart contracts refer to a set smart contracts that are deployed on multiple chains(evm-compatible chains for current version), and provided for Exocore users(mainly stakers) to interact with Exocore system from specific client chain. And most of its administrative functionalities are only acccessble for Exocore validator set via valid TSS signature forwarded by some third-party bridge(Layerzero) or Exocore itself.

As the two main functionalities of client chain smart contracts include:

1. Take user funds into custody when users ask to enter Exocore system, update user balance periodically and deal with withdrawal request of user based on withdrawable balance.
2. Forward user request from client chain side to Exocore validator set, as well as receive response from Exocore validator set to update state or execute some operations.

We have these components included in Exocore client chain smart contracts architecture:

1. `Gateway`: This is the entry point where client chain users make request to Exocore validator set, as well as the end point that receives cross-chain messages from Exocore validator set.
2. `Vault`: This is where user funds are taken into custody and managed. Within `Vault`, user balance is updated periodically by Exocore validator set through cross-chain message to reveal user’s real position(after slashing, rewarding and other impact). Users can withdraw from `Vault` based on grant from Exocore validator set. Every specific asset should have standalone `Vault`.
3. `Controller`: The controller that is responsible for managing multiple `Vault`s. It should be the entry point for operations on `Vault`, as well as the entry point for user’s interactions with Exocore validator set.

## Upgrade

Upgradeable contracts rely on three components: storage contract, logic contract, proxy contract. All upgradeable contracts architecture utilizes the fact that inside a proxy contract, if we `delegatecall` the logic contract, the code of logic contract would be loaded in the context of the proxy contract. Therefore proxy contract could actually forward the call to a logic contract but read and write proxy’s own state variables, and reading or writing the state variables of logic contract would modify the corresponding slot of proxy contract. That way, proxy contract could inherit the old state(and even add state variable) but replacing the logic contract. Because after upgrade, the new logic contract with new implementation should align the storage with proxy storage layout by only extending the proxy storage layout(no state variables should be removed, and the type as well as the order of state variable should remain the same), all versions of logic contract should inherit the same storage contract to make storage layout compatible after upgrade. Afterwards, by replacing the old logic contract address to the address of new logic contract, we could upgrade a contract without violating its storage. 

In this architecture, proxy contract would not inherit the storage contract and keep as stateless as possible.

For the purpose of allowing adding state variables to proxy contract, usually we need to remain some unused slots in the end of storage contract so that we could add new state variables and override the unused slots.

```solidity
abstract contract DelegationManagerStorage is IDelegationManager {
......
/**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[44] private __gap;
}
```

Besides all of these techniques, there are other details that we need to handle when designing upgradeable contracts, like function signature collision and forbidding initializing state variables in `constructor` and so on. Openzeppelin’s `TransparentUpgradeableProxy` and upgradeable implementation of token standards like `ERC20Upgradeable` handle details properly.

1.  `TransparentUpgradeableProxy` would store the meta state variables like logic contract address to random slots to avoid state variable storage layout collision.
2. https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable follow the upgradeable design by:

> constructors are replaced by initializer functions, state variables are initialized in initializer functions, and we additionally check for storage incompatibilities across minor versions.
> 

In most of cases, we can not directly use implementations in https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable and need to implement our own upgradeable contracts. When we write our own upgradeable smart contracts, we must follow these principles:

1. upgradeable contract should always inherit from upgradeable contracts.
2. Do not assign an initial value to state variables when declaring them except `immutable` and `constant` .
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

On the other hand, openzeppelin’s doc suggests using `[UUPSUpgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable)` while `[TransparentUpgradeableProxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#TransparentUpgradeableProxy)` being the most popular upgradeable proxy. We could explore `[UUPSUpgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable)` while reserve the plan of using `[TransparentUpgradeableProxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#TransparentUpgradeableProxy)` .

For more details please refer to these docs:

[Proxy Upgrade Pattern - OpenZeppelin Docs](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies#the-constructor-caveat)

[Writing Upgradeable Contracts - OpenZeppelin Docs](https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable)

## `Gateway`

Similar to LayerZero `endpoint`, `Gateway` is mainly responsible for sending cross-chain messages and receiving cross-chain messages. The validity of cross-chain messages are guaranteed by LayerZero oracle and relayer if integrated with LayerZero protocol, otherwise `Gateway` itself should validate the cross-chain messages.

Eventually, Exocore validator set should be the owner of `Gateway` so that it can update some state variables or even upgrade it in the future. At the early stage, we still need more controlled way to upgrade, meaning upgrade by multisig.

`Gateway` is also the router that forwards messages from Exocore validator set to its destination contract to be handled. Currently this mainly refers to forwarding response from Exocore validator set to `Controller` to execute the messages.

We could make `Gateway` contract upgradable so that we could inherit the state while adding or removing some logics in the future.

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

### `sendInterchainMsg`

If intergrating with LayerZero, the implementation of this function should call LayzerZero `endpoint` with corresponding arguments from `msg`, otherwise this function is the `endpoint` for cross-chain request from the client chain. In both cases, event `InterchainMsgSent` should be emmitted.

This function is only accessible for Exocore-controlled contracts like `Controller`, and only contracts that intend to send cross-chain requests to Exocore validator set could call this function. For example, in deposit workflow, `Controller` could only call this function to send deposit requests to Exocore validator set after locking user funds into the `Vault`, thus ensuring the deposit request is valid.

Generally speaking, if no unauthorized contracts or EOA addresses call this function, this function should be safe. Therefore, the implementation of `Gateway` contract should maintain the authorized contracts in a whitelist and restrict the accessibility of this function to the whitelist. While for the counterparty that receives the message in Exocore chain, it should check that the message is originated from trusted remote contract.

### `receiveInterchainMsg`

If integrating with LayerZero, `Gateway` contract should implement interface `ILayerZeroReceiver` and this function should be wrapped into `lzReceive` function to receive the cross-chain message relayed by LayerZero and sent from LayerZero `endpoint` on this client chain:

```solidity
function lzReceive(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload) external;
```

The implementation of this function should forward the received message to destination contract. For example, when a user asks to deposit to Exocore, Exocore validator set should respond with a message indicating whether the accounting for the deposited assets is successful, in this case, `receiveInterchainMsg` should call `Controller.call(payload)` to forward the payload to `Controller` (the destination) to inform the controller that the despoit is successful or failed for next step operation.

This function should be only accessible for LayerZero `endpoint` to send cross-chain message. And for security reason, before actally executing the message, the function should check that the message is originated from the Exocore validor set by verifying the TSS signature or other means.

## `Vault`

Every whitelisted native token on the client chain for Exocore has a standalone `Vault` used for user funds custody.

Exocore validator set should be the owner of `Vault` so that it can update some state variables or even upgrade it in the future.

This is where the user’s deposited funds are actually taken into custody. Generally speaking, user enter Exocore system by locking assets in `Vault` and leave Exocore system by unlocking all of the withdraw-able amount of assets in `Vualt`, which could be less than the total deposited amount but not greater after possible slashing, as well as collecting all of the rewards elsewhere. Between the first deposit and final withdrawal, Exocore validator set would update the user balance in `Vault` periodically through `Gateway` if there is any change.

Especially for user withdrawal of deposited assets, use should apply for the withdrawal first before the user could actually withdraw the assets into destination address. `Gateway` would forward this withdrawal request to Exocore validator set, and after all necessary checks and computations, Exocore validator set would response with the withdrawal grant message. After receiving the withdrawal grant message and checked that `granted` as true, at least two operations should be executed:

1. Accurately update the user balance in `Vualt`.
2. Unlock the intended amount of tokens after checking against the updated user balance.

Otherwise the user’s withdrawal request would be rejected.

`Vualt` contract should be considered as upgradeable so that we could add or remove logics or even add more state variables in the future.

```solidity
interface IVault {
	function withdraw(address recipient, uint256 amount) external payable;

    function deposit(address sender, uint256 amount) external;

    function updatePrincipalBalance(address user, uint256 principalBalance) external;

    function updateRewardBalance(address user, uint256 rewardBalance) external;

    function updateWithdrawableBalance(address user, uint256 unlockAmount) external;
}
```

`principalBalance` refers to the principal that the user deposits into Exocore chain. This part is separated from the rewarding part of user assets on Exocore, as rewarding assets could be distributed on Exocore chain or on another client chain while the user principal is taken in custody in user’s client chain smart contracts. Besides we assume that the principal balance would only in influenced by slash and it should not be transferrable to another user on Exocore chain, which means that the principal balance would never be greater than the total deposited principal.

### `deposit`

The implementation of this function should transfer user funds into `Vualt` address and update user balance correspondingly.

This function should be only accessible for `Controller` so that this function could only work as part of the process of the whole deposit workflow and ensure the whole workflow is controlled by `Controller`.

For security reason, we must call this function to lock user funds before the deposit request is forwarded to Exocore validator set and accounted.

### `withdraw`

The implementation of this function should check against user’s clien chain balance and transfer the specified amount of token to destination address.

This function should be only accessible for `Controller` so that this function could only work as part of the process of the whole withdraw workflow and ensure the whole workflow is controlled by `Controller`.

This function could only deduct the clien chain balance, which is updated when each time user calls `Controller.withdrawPrincipalFromExocore` and `UserBalance.withdrawAmount` would be added to user’s client chain token balance.

Considering system security, Exocore validator set must return the correct `UserBalance.withdrawAmount` each time responding to `Controller.withdrawPrincipalFromExocore` and the function should check two invariants at the end of the function:

1. After `withdraw` process finishes, the user’s client chain balance should never increase.
2. The withdraw amount should never be greater than the `totalDepositedBalance`.

## `Controller`

`Controller` is the manager of all `Vaults`, as well as the entry point where users call to interact with Exocore system and Exocore validator set calls to update client chain state.

Exocore validator set should be the owner of `Controller` so that it can update some state variables or even upgrade it in the future.

```solidity
interface IController {

    event DepositResult(address indexed depositor, bool indexed success, uint256 amount);
    event WithdrawResult(address indexed withdrawer, bool indexed success, uint256 amount);
    event DelegateResult(address indexed delegator, address indexed delegatee, bool indexed success, uint256 amount);

    /// *** function signatures for staker operations ***

    /**
     * @notice Client chain users call to deposit to Exocore system for further operations like delegation, staking...
     * @dev This function should:
     * 1) lock the @param amount of @param token into vault.
     * 2) ask Exocore validator set to account for the deposited @param amount of @param token.
     * Deposited assets should remain locked until Exocore validator set responds with success or faulure.
     * @param token - The address of specific token that the user wants to deposit.
     * @param amount - The amount of @param token that the user wants to deposit.
     */
    function deposit(address token, uint256 amount) external payable;

    /**
     * @notice Client chain users call to delegate deposited token to specific node operator.
     * @dev This assumes that the delegated assets should have already been deposited to Exocore system.
     * @param operator - The address of a registered node operator that the user wants to delegate to.
     * @param token - The address of specific token that the user wants to delegate to.
     * @param amount - The amount of @param token that the user wants to delegate to node operator.
     */
    function delegateTo(address operator, address token, uint256 amount) external;

    /**
     * @notice Client chain users call to withdraw principal from Exocore to client chain before they are granted to withdraw from the vault.
     * @dev This function should ask Exocore validator set for withdrawal grant. If Exocore validator set responds
     * with true or success, the corresponding assets should be unlocked to make them claimable by users themselves. Otherwise
     * these assets should remain locked.
     * @param token - The address of specific token that the user wants to withdraw from Exocore.
     * @param principalAmount - principal means the assets user deposits into Exocore for delegating and staking.
     * we suppose that After deposit, its amount could only remain unchanged or decrease owing to slashing, which means that direct
     * transfer of principal is not possible.
     */
    function withdrawPrincipalFromExocore(address token, uint256 principalAmount) external;

    /**
     * @notice Client chain users call to claim their unlocked assets from the vault.
     * @dev This function assumes that the claimable assets should have been unlocked before calling this.
     * @dev This function does not ask for grant from Exocore validator set.
     * @param token - The address of specific token that the user wants to claim from the vault.
     * @param amount - The amount of @param token that the user wants to claim from the vault.
     * @param distination - The destination address that the assets would be transfered to.
     */
    function claim(address token, uint256 amount, address recipient) external;
}
```

### `deposit`

This function handles the workflow of deposit process. The generaly deposit workflow is as follows:

1. find the targeted `Vault` based on token type and call `Vault.deposit` to take user funds into custody.
2. If step 1 succeed, call `Gateway.sendInterchainMsg` to send deposit request to Exocore chain so that Exocore validator set could account for the deposited tokens.

As cross-chain communication is asynchronous, upon steps would finish in one transaction. After this transaction finishs with success, Exocore chain is expected to deal with the deposit request correctly and returns a response indicating whether the deposit is successful or not:

1. Relayer call `Gateway.receiveInterchainMsg` to send Exocore chain response. If the result is a success, emit the corresponding event in `Controller` to inform the user that deposit is successful and update `UserBalance` in `Vualt`. Otherwise emit the corresponding event in `Controller` to inform the user that deposit is failed and update user’s claimable balance correspondingly.

This function should be accessible for any EOA address and contract address.

In aspect of security, the implementation should strictly follow the designed workflow order and ensure there is no chance for false deposit.

### `delegateTo`

This function controlls the delegation workflow for client chain user. It assumes that there is enough amount of tokens deposited into the Exocore system before delegation, otherwise the delegation would fail.

The delegation workflow is also separated into two transactions:

1. client chain transaction by user: call `Gateway.sendInterchainMsg` to send delegate request to Exocore chain.
2. client chain transaction by Exocore validator set: call `Gateway.receiveInterchainMsg` to inform whether the delegation is successful or not.

This function should be accessible for any EOA address and contract address.

In aspect of security, this should not change the client chain state especially considering user balance.

### `withdrawPrincipalFromExocore`

This function is aimed for user withdrawing principal from Exocore chain to client chain. This involves the correct accounting on Exocore chain as well as the correct update of user’s `principalBalance` and claimable balance. If this process is successful, user should be able to claim the corresponding assets on client chain to destination address.

The principal withdrawal workflow is also separated into two trasactions:

1. client chain transaction by user: call `Gateway.sendInterchainMsg` to send principal withdrawal request to Exocore chain.
2. client chain transaction by Exocore validator set: call `Gateway.receiveInterchainMsg` to receive the response from Exocore chain, and call `unlock` to update user’s `principalBalance` and claimable balance. If response indicates failure, no user balance should be modified.

This function should be accessible for any EOA address and contract address.

In aspect of security, Exocore chain must have successfully updated user balance on Exocore chain and checked against user’s withdraw-able balance.

The withdraw-able amount of principal is defined as follows:

1. The asset is not staked (delegated) on any operators.
2. The asset is not frozen/slashed.
3. The asset is not in unbonding state.

### `claim`

This function is aimed for user claiming the unlocked amount of principal. Before claiming, user must make sure that thre is enogh principal unlocked by calling `withdrawPrincipalFromExocore`. The implementaion of this function should check against user’s claimable balance and transfer tokens to the destination address that user specified.

This function should be accessible for any EOA address and contract address.

In aspect of security, we must carefully check against user’s claimable(unlocked) principal balance.
