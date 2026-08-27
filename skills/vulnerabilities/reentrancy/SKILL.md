---
name: reentrancy
description: Comprehensive guide to Reentrancy attacks in smart contracts
tags: ["vuln", "reentrancy"]
---

# Reentrancy Security & Attack Vectors

### 1. Read-Only Reentrancy
- **Mechanism**: A view function (e.g. `getPrice()`, `getVirtualPrice()`) reads temporary, unfinalized state from an external protocol while that protocol is inside an external callback or flash loan hook.
- **Example**: Curve LP token price queried during ETH removal callback; attacker borrows via flash loan, inflates perceived collateral price during hook, borrows excess funds from victim protocol, then completes withdrawal.
- **Remediation**: Add non-reentrant guards to view functions that update state flags or check transient lock status before returning price queries.

### 2. Cross-Contract & Cross-Function Reentrancy
- **Mechanism**: Function A modifies shared state (e.g. `withdraw()`) with reentrancy guard, but Function B (e.g. `transfer()`, `liquidate()`, or Strategy call) modifies or relies on the same state variable without sharing the mutex.
- **Remediation**: Use global or shared reentrancy guards across all interdependent contracts, or strictly adhere to Checks-Effects-Interactions (CEI).

### 3. ERC-777 / ERC-1155 Token Callback Hijacking
- **Mechanism**: ERC-777 `tokensToSend` / `tokensReceived` or ERC-1155 `onERC1155Received` hook execution before internal state updates.
- **Remediation**: Apply CEI pattern strictly: burn/transfer internal accounting before executing external token transfers.
