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

## Upgrade

For every upgradable contract, we should first think about using openzeppelin's implementation in `OpenZeppelin/openzeppelin-contracts-upgradeable`. If there is no corresponding upgradeable implementation, we should put the upgradable contract behind the `UUPSUpgradeable` proxy and call the proxy instead.

## `Gateway`

Similar to LayerZero `endpoint`, `Gateway` is mainly responsible for sending cross-chain messages and receiving cross-chain messages. The validity of cross-chain messages are guaranteed by LayerZero oracle and relayer if integrated with LayerZero protocol, otherwise `Gateway` itself should validate the cross-chain messages.

Exocore validator set should be the owner of `Gateway` so that it can update some state variables or even upgrade it in the future.

`Gateway` is also the router that forwards messages from Exocore validator set to its destination contract to be handled. Curretly this mainly refers to forwarding response from Exocore validator set to `Controller` to execute the messages.

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

This is where the user's deposited funds are actually taken into custody. Generally speaking, user enter Exocore system by locking assets in `Vault` and leave Exocore system by unlocking all of the withdraw-able amount of assets in `Vualt`, which could be less than the total deposited amount but not greater after possible slashing, as well as collecting all of the rewards elsewhere. Between the first deposit and final withdrawal, Exocore validator set would update the user balance in `Vault` periodically through `Gateway` if there is any change.

Especially for user withdrawal of deposited assets, use should apply for the withdrawal first before the user could actually withdraw the assets into destination address. `Gateway` would forward this withdrawal request to Exocore validator set, and after all necessary checks and computations, Exocore validator set would response with the withdrawal grant message. After receiving the withdrawal grant message and checked that `granted` as true, at least two operations should be executed:

1. Accurately update the user balance in `Vualt`.
2. Unlock the intended amount of tokens after checking against the updated user balance.

Otherwise the user's withdrawal request would be rejected.

`Vualt` contract should be considered as upgradeable so that we could add or remove logics or even add more state variables in the future.

```solidity
interface IVault {
    struct UserBalance {
        address user;
        uint256 ExocoreCapitalBalance;
        uint256 withdrawAmount;
    }

    function claim(address recipient, uint256 amount) external payable;

    function deposit(address sender, uint256 amount) external;

    function refreshUserBalance(address user, UserBalance calldata balance) external;
}
```

`ExocoreCapitalBalance` refers to the capital that the user deposits into Exocore chain. This part is separated from the rewarding part of user assets on Exocore, as rewarding assets could be distributed on Exocore chain or on another client chain while the user capital is taken in custody in user's client chain smart contracts. Besides we assume that the capital balance would only in influenced by slash and it should not be transferrable to another user on Exocore chain, which means that the capital balance would never be greater than the total deposited capital.

### `deposit`

The implementation of this function should transfer user funds into `Vualt` address and update user balance correspondingly.

This function should be only accessible for `Controller` so that this function could only work as part of the process of the whole deposit workflow and ensure the whole workflow is controlled by `Controller`.

For security reason, we must call this function to lock user funds before the deposit request is forwarded to Exocore validator set and accounted.

### `claim`

The implementation of this function should check against user's clien chain balance and transfer the specified amount of token to destination address.

This function should be only accessible for `Controller` so that this function could only work as part of the process of the whole withdraw workflow and ensure the whole workflow is controlled by `Controller`.

This function could only deduct the clien chain balance, which is updated when each time user calls `Controller.withdrawCapitalFromExocore` and `UserBalance.withdrawAmount` would be added to user's client chain token balance.

Considering system security, Exocore validator set must return the correct `UserBalance.withdrawAmount` each time responding to `Controller.withdrawCapitalFromExocore` and the function should check two invariants at the end of the function:

1. After `claim` process finishes, the user's client chain balance should never increase.
2. The claim amount should never be greater than the `totalDepositedBalance`.

### `refreshUserBalance`

This function should only be called by Exocore validator set through `Gateway` to update user's Exocore chain capital balance and clien chain balance. Along with `ExocoreCapitalBalance`, there is a field `withdrawAmount` indicating the amount of capital token that is withdrawn from Exocore chain to client chain, and it should be used to update user's client chain balance in this function.

This function should be only accessible for `Controller` so that this function could only work as part of the process of the whole withdraw workflow or periodic update from Exocore chain and ensure the whole workflow is controlled by `Controller`.

This function relies on the Exocore set correctly returning the updated `ExocoreCapitalBalance` and `withdrawAmount`.

Everytime the user is trying to withdraw capital from Exocore chain, this function must be called by Exocore validator set via cross-chain message to correctly update user's Exocore capital balance and especially correct `withdrawAmount` to update user's claimable amount on client chain.


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
     * @notice Client chain users call to withdraw capital from Exocore to client chain before they are granted to withdraw from the vault.
     * @dev This function should ask Exocore validator set for withdrawal grant. If Exocore validator set responds
     * with true or success, the corresponding assets should be unlocked to make them claimable by users themselves. Otherwise
     * these assets should remain locked.
     * @param token - The address of specific token that the user wants to withdraw from Exocore.
     * @param capitalAmount - capital means the assets user deposits into Exocore for delegating and staking.
     * we suppose that After deposit, its amount could only remain unchanged or decrease owing to slashing, which means that direct
     * transfer of capital is not possible.
     */
    function withdrawCapitalFromExocore(address token, uint256 capitalAmount) external;

    /**
     * @notice Client chain users call to claim their unlocked assets from the vault.
     * @dev This function assumes that the claimable assets should have been unlocked before calling this.
     * @dev This function does not ask for grant from Exocore validator set.
     * @param token - The address of specific token that the user wants to claim from the vault.
     * @param amount - The amount of @param token that the user wants to claim from the vault.
     * @param distination - The destination address that the assets would be transfered to.
     */
    function claim(address token, uint256 amount, address distination) external;

    /// *** function signatures for commands of Exocore validator set forwarded by Gateway ***

    /**
     * @notice Exocore validator set calls this through Gateway contract to grant the withdrawal from Exocore
     * to clien chain by unlocking the corresponding assets in the vault.
     * @dev Only Exocore validato set could indirectly call this function through Gateway contract. 
     * @param withdrawer - The address of specific withdrawer that Exocore validator set grants for withdrawal.
     * @param token - The address of specific token that Exocore validator set grants for withdrawal.
     * @param amount - The amount of @param token that Exocore validator set grants for withdrawal.
     */
    function grantWithdrawal(address withdrawer, address token, uint256 amount) external;
}
```

### `deposit`

This function handles the workflow of deposit process. The generaly deposit workflow is as follows:

1. find the targeted `Vault` based on token type and call `Vault.deposit` to take user funds into custody.
2. If step 1 succeed, call `Gateway.sendInterchainMsg` to send deposit request to Exocore chain so that Exocore validator set could account for the deposited tokens.

As cross-chain communication is asynchronous, upon steps would finish in one transaction. After this transaction finishs with success, Exocore chain is expected to deal with the deposit request correctly and returns a response indicating whether the deposit is successful or not:

3. Relayer call `Gateway.receiveInterchainMsg` to send Exocore chain response. If the result is a success, emit the corresponding event in `Controller` to inform the user that deposit is successful and update `UserBalance` in `Vualt`. Otherwise emit the corresponding event in `Controller` to inform the user that deposit is failed and update user's claimable balance correspondingly.

This function should be accessible for any EOA address and contract address.

In aspect of security, the implementation should strictly follow the designed workflow order and ensure there is no chance for false deposit.

### `delegateTo`

This function controlls the delegation workflow for client chain user. It assumes that there is enough amount of tokens deposited into the Exocore system before delegation, otherwise the delegation would fail.

The delegation workflow is also separated into two transactions:

1. client chain transaction by user: call `Gateway.sendInterchainMsg` to send delegate request to Exocore chain.
2. client chain transaction by Exocore validator set: call `Gateway.receiveInterchainMsg` to inform whether the delegation is successful or not.
   
This function should be accessible for any EOA address and contract address.

In aspect of security, this should not change the client chain state especially considering user balance.

### `withdrawCapitalFromExocore`

This function is aimed for user withdrawing capital from Exocore chain to client chain. This involves the correct accounting on Exocore chain as well as the correct update of user's `ExocoreCapitalBalance` and claimable balance. If this process is successful, user should be able to claim the corresponding assets on client chain to destination address.

The capital withdrawal workflow is also separated into two trasactions:

1. client chain transaction by user: call `Gateway.sendInterchainMsg` to send capital withdrawal request to Exocore chain.
2. client chain transaction by Exocore validator set: call `Gateway.receiveInterchainMsg` to receive the response from Exocore chain, and call `grantWithdrawal` to update user's `ExocoreCapitalBalance` and claimable balance. If response indicates failure, no user balance should be modified.

This function should be accessible for any EOA address and contract address.

In aspect of security, Exocore chain must have successfully updated user balance on Exocore chain and checked against user's withdraw-able balance.

The withdraw-able amount of capital is defined as follows:

1. The asset is not staked (delegated) on any operators.
2. The asset is not frozen/slashed.
3. The asset is not in unbonding state.

### `claim`

This function is aimed for user colaming the unlocked amount of capital. Before claiming, user must make sure that thre is enogh capital unlocked by calling `withdrawCapitalFromExocore`. The implementaion of this function should check against user's claimable balance and transfer tokens to the destination address that user specified.

This function should be accessible for any EOA address and contract address.

In aspect of security, we must carefully check against user's claimable(unlocked) capital balance.

### `grantWithdrawal`

This function is only called when user initiates the withdrawal process. Exocore validator set calls this to unlock the corresponding amount of capital and update user's `ExocoreCapitalBalance`.

This function should only be indirectly accessible for Exocore validator set though `Gateway`.

In aspect of security, before `grantWithdrawal` during withdraw process, user's claimable capital balance should not be updated.


