---
name: 03_threat_modeling
description: Threat Modeling, Access Control & Invariants Phase Checklist
tags: ["threat_modeling"]
---

# Threat Modeling & Invariants Checklist

1. **Access Control Matrix**:
   - Document all privileged actors: `Admin`, `Owner`, `Operator`, `Liquidator`, `Vault`, `Public`.
   - List every function restricted by modifiers (`onlyOwner`, `onlyRole`, `whenNotPaused`).
   - Record roles via `state_update add_actor_role`.

2. **Core Protocol Invariants**:
   - Solvency: Total assets deposited must always cover total minted liabilities (`totalAssets >= totalSupply`).
   - Conservation: Token balances inside the contract must equal the sum of user balances plus accumulated protocol fees.
   - Monotonicity: Non-decreasing accumulators (e.g. cumulative interest index).
   - Record invariants via `state_update add_invariant`.

3. **Asset & Value Flow Mapping**:
   - Map entry points where user deposits funds.
   - Map exit points where funds are withdrawn, redeemed, or liquidated.
   - Identify who captures fees, arbitrage, or yield.
