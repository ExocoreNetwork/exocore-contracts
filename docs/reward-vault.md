# Reward Vault Design Document

## 1. Overview

The Reward Vault is a crucial component of the Exocore ecosystem, designed to securely custody reward tokens distributed by the Exocore chain. It supports permissionless reward token deposits on behalf of AVS (Actively Validated Service) providers and allows stakers to claim their rewards after verification by the Exocore chain. The Reward Vault is managed by the Gateway contract, which acts as an intermediary for all operations.

## 2. Design Principles

2.1. Permissionless Reward System:
    - The Reward Vault should handle standard ERC20 tokens without requiring prior whitelisting or governance approval.
    - Depositors should be able to deposit rewards in any standard ERC20 token on behalf of AVS providers without restrictions.

2.2. Exocore Chain as Source of Truth: The Exocore chain maintains the record of reward balances and handles reward distribution/accounting for each staker. The Reward Vault only tracks withdrawable balances after claim approval.

2.3. Separation of Concerns: The Reward Vault is distinct from principal vaults, maintaining a clear separation between staked principals and earned rewards.

2.4. Security: Despite its permissionless nature, the Reward Vault must maintain high security standards to protect users' rewards.

2.5. Gateway-Managed Operations: All interactions with the Reward Vault are managed through the Gateway contract, ensuring consistency with the existing architecture.

## 3. Architecture

### 3.1. Smart Contract: RewardVault.sol

Key Functions:
- `deposit(address token, address avs, uint256 amount)`: Allows the Gateway to deposit reward tokens on behalf of an AVS. Increases the AVS's balance for the specified token.
- `updateWithdrawableBalance(address token, address avs, address withdrawer, uint256 amount)`: Allows the Gateway to update a staker's withdrawable balance after claim approval. Decreases the AVS's balance and increases the withdrawer's withdrawable balance.
- `withdraw(address token, address withdrawer, uint256 amount)`: Allows the Gateway to withdraw claimed rewards for a staker.
- `getWithdrawableBalance(address token, address staker)`: Returns the withdrawable balance of a specific reward token for a staker.
- `getAVSBalance(address token, address avs)`: Returns the balance of a specific reward token for an AVS.

### 3.2. Smart Contract: ClientChainGateway.sol (existing contract, modified)

New Functions:
- `submitReward(address token, address avs, uint256 amount)`: Receives reward submissions and calls RewardVault's `deposit`.
- `claimReward(address token, address avs, uint256 amount)`: Initiates a claim request to the Exocore chain.
- `withdrawReward(address token, address recipient, uint256 amount)`: Calls RewardVault's `withdraw` to transfer claimed rewards to the recipient.

### 3.3. Data Structures

#### 3.3.1. Withdrawable Balances Mapping (in RewardVault.sol)

```solidity
mapping(address => mapping(address => uint256)) public withdrawableBalances;
```

This nested mapping tracks withdrawable reward balances:
- First key: Token address
- Second key: Staker address
- Value: Withdrawable balance amount

#### 3.3.2. AVS Balances Mapping (in RewardVault.sol)

```solidity
mapping(address => mapping(address => uint256)) public avsBalances;
```

This nested mapping tracks the balance of each AVS for each token:
- First key: Token address
- Second key: AVS address
- Value: Balance amount

## 4. Key Processes

### 4.1. Reward Submission

1. Depositor calls `submitReward` on the Gateway, specifying the token, amount, and AVS ID.
2. Gateway calls RewardVault's `deposit`, which:
   a. Transfers the specified amount of tokens from the depositor to itself.
   b. Increases the AVS's balance for the specified token in the `avsBalances` mapping.
3. Gateway sends a message to the Exocore chain to account for the deposited rewards.
4. Exocore chain processes the request, which must succeed to ensure correct accounting.

### 4.2. Reward Distribution and Accounting

1. Exocore chain handles the distribution and accounting of rewards to stakers based on their staking activities and the rewards submitted.
2. Exocore chain maintains the record of each staker's earned rewards.

### 4.3. Reward Claiming and Withdrawal

1. Staker calls `claimReward` on the Gateway.
2. Gateway sends a claim request to the Exocore chain.
3. Exocore chain verifies the request and sends a response back to the Gateway.
4. Gateway calls RewardVault's `updateWithdrawableBalance`, which:
   a. Decreases the AVS's balance for the specified token in the `avsBalances` mapping.
   b. Increases the staker's withdrawable balance for the specified token in the `withdrawableBalances` mapping.
5. At any time after claiming, the staker can call `withdrawReward` on the Gateway.
6. Gateway calls RewardVault's `withdraw` to transfer the tokens from the vault to the staker's address.

## 5. Security Considerations

5.1. Access Control: 
- Only the Gateway should be able to call RewardVault's functions.
- Any address should be able to call `ClientChainGateway.submitReward`.
- Only stakers should be able to call `ClientChainGateway.claimReward` for their own rewards.

5.2. Token Compatibility: While the system is permissionless, it is designed to work with standard ERC20 tokens to ensure consistent behavior and accounting.

5.3. Balance Integrity: Ensure that the sum of all AVS balances and withdrawable balances for a given token always equals the total token balance held by the Reward Vault.

## 6. Gas Optimization

6.1. Batch Operations: Consider implementing functions for batch reward submissions and claims to reduce gas costs.

## 7. Upgradability

The Reward Vault should be implemented as an upgradeable contract using the OpenZeppelin Upgrades plugin. The contract owner, which will be a multisig wallet controlled by the protocol governors, will have the ability to upgrade the contract. This allows for future improvements and bug fixes while maintaining transparency and security.

## 8. Events

Emit events for all significant actions:
- `RewardSubmitted(address indexed token, address indexed avs, address indexed depositor, uint256 amount)`
- `RewardClaimed(address indexed token, address indexed avs, address indexed staker, uint256 amount)`
- `RewardWithdrawn(address indexed token, address indexed staker, uint256 amount)`

## 9. Future Considerations

9.1. Reward Analytics: Implement functions to track total rewards submitted for each AVS and total rewards claimed by stakers. This can now leverage the `avsBalances` mapping for more detailed analytics.

9.2. Emergency Withdrawal: Consider an emergency withdrawal function for unclaimed rewards, accessible only by governance in case of critical issues. This should take into account both `avsBalances` and `withdrawableBalances`.

9.3. AVS Balance Reporting: Implement a function to report the total balance across all tokens for a given AVS, which could be useful for AVS providers to track their reward distribution.
