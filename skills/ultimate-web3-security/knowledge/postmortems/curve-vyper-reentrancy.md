# Post-Mortem: Curve Finance (0M Exploit)

- **Date:** July 30, 2023
- **Protocol Archetype:** DEX / AMM Pool
- **Root Cause Category:** Read-Only View Reentrancy & Compiler Lock Failure
- **Target Invariant Broken:** `INV-02` (Checks-Effects-Interactions & State Isolation)

## 1. Vulnerability Mechanics
Specific versions of the Vyper compiler (0.2.15, 0.2.16, 0.3.0) incorrectly handled reentrancy lock storage slot allocation.
When `@nonreentrant('lock')` was placed on multiple functions (e.g. `remove_liquidity()` and `add_liquidity()`), the compiler generated separate, isolated storage slots for each function rather than sharing a single global reentrancy lock.

## 2. Attack Walkthrough
1. Attacker calls `remove_liquidity()` on a Curve pool (e.g. pETH/ETH, alETH/ETH, CRV/ETH).
2. During the raw ETH transfer to the attacker's contract, the attacker's `receive()` hook is triggered.
3. Inside the hook, pool balances are temporarily unbalanced, but the pool's internal `virtual_price` has not updated.
4. Because the reentrancy lock on `add_liquidity()` used a different storage slot, the attacker re-entered `add_liquidity()` at the distorted exchange rate, minting vastly more LP tokens than deposited.
5. Attacker withdrew all assets, draining 0M+.

## 3. Key Takeaways & Defense Matrix
- **Rule:** Always verify that reentrancy guards are shared globally across all public entry points.
- **Lens Check:** Audit raw ETH transfers and view reentrancy on all liquidity pricing functions.
