# Reward Vault Design Document

## 1. Overview

The Reward Vault is a crucial component of the Exocore ecosystem, designed to securely custody reward tokens distributed by the Exocore chain. It supports permissionless reward token deposits on behalf of AVS (Actively Validated Service) providers and allows stakers to claim their rewards after verification by the Exocore chain.

## 2. Design Principles

2.1. Permissionless Reward System:
    - The Reward Vault should handle standard ERC20 tokens without requiring prior whitelisting or governance approval.
    - Depositors should be able to deposit rewards in any standard ERC20 token on behalf of AVS providers without restrictions.

2.2. Exocore Chain as Source of Truth: The Exocore chain maintains the record of reward balances and handles reward distribution/accounting for each staker. The Reward Vault only tracks withdrawable balances after claim approval.

2.3. Separation of Concerns: The Reward Vault is distinct from principal vaults, maintaining a clear separation between staked principals and earned rewards.

2.4. Security: Despite its permissionless nature, the Reward Vault must maintain high security standards to protect users' rewards.

## 3. Architecture

### 3.1. Smart Contract: RewardVault.sol

Key Functions:
- `submitReward(address token, uint256 amount, address avs)`: Allows depositors to deposit reward tokens on behalf of an AVS.
- `claimReward(address token, uint256 amount)`: Allows stakers to claim their approved rewards, updating their withdrawable balance.
- `withdrawReward(address token, uint256 amount)`: Allows stakers to withdraw their claimed rewards.
- `getWithdrawableBalance(address token, address staker)`: Returns the withdrawable balance of a specific reward token for a staker.

### 3.2. Data Structures

#### 3.2.1. Withdrawable Balances Mapping

```solidity
mapping(address => mapping(address => uint256)) internal _withdrawableBalances;
```

This nested mapping tracks withdrawable reward balances:
- First key: Token address
- Second key: Staker address
- Value: Withdrawable balance amount

## 4. Key Processes

### 4.1. Reward Submission

1. Depositor calls `submitReward` on the Reward Vault, specifying the token, amount, and AVS ID.
2. Reward Vault transfers the specified amount of tokens from the depositor to itself.
3. Reward Vault sends a message to the Exocore chain to account for the deposited rewards.
4. Exocore chain processes the request, which must succeed to ensure correct accounting.

### 4.2. Reward Distribution and Accounting

1. Exocore chain handles the distribution and accounting of rewards to stakers based on their staking activities and the rewards submitted.
2. Exocore chain maintains the record of each staker's earned rewards.

### 4.3. Reward Claiming and Withdrawal

1. Staker initiates a claim request through the Exocore chain.
2. Exocore chain verifies the request and approves the claim if valid.
3. Staker calls `claimReward` on the Reward Vault with the approved amount.
4. Reward Vault verifies the claim with Exocore chain and updates the staker's withdrawable balance.
5. At any time after claiming, the staker can call `withdrawReward` to transfer the tokens from the vault to their address.

## 5. Security Considerations

5.1. Access Control: 
- Any address should be able to call `submitReward`.
- Only stakers should be able to call `claimReward` for their own rewards.

5.2. Token Compatibility: While the system is permissionless, it is designed to work with standard ERC20 tokens to ensure consistent behavior and accounting.

## 6. Gas Optimization

6.1. Batch Operations: Consider implementing functions for batch reward submissions and claims to reduce gas costs.

## 7. Upgradability

The Reward Vault should be implemented as an upgradeable contract using the OpenZeppelin Upgrades plugin. The contract owner, which will be a multisig wallet controlled by the protocol governors, will have the ability to upgrade the contract. This allows for future improvements and bug fixes while maintaining transparency and security.

## 8. Events

Emit events for all significant actions:
- `RewardSubmitted(address indexed token, address indexed avs, address indexed depositor, uint256 amount)`
- `RewardClaimed(address indexed token, address indexed staker, uint256 amount)`
- `RewardWithdrawn(address indexed token, address indexed staker, uint256 amount)`

## 9. Future Considerations

9.1. Reward Analytics: Implement functions to track total rewards submitted for each AVS and total rewards claimed by stakers.

9.2. Emergency Withdrawal: Consider an emergency withdrawal function for unclaimed rewards, accessible only by governance in case of critical issues.
