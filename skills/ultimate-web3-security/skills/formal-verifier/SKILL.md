---
name: formal-verifier
description: Symbolic property verification & formal invariant synthesis sub-skill using Halmos and Kontrol for the ultimate-web3-security pipeline. Loaded in Phase 4/6 for mathematical soundness verification.
---

# Formal Verifier (Halmos & Symbolic Invariant Testing)

Provides mathematical certainty across $2^{256}$ input states using bounded symbolic execution (Halmos / Kontrol).

## 1. When to Deploy Symbolic Verification

- Critical mathematical operations: `mulDiv`, share conversions, dynamic interest rates, debt compounding.
- Roundtrip conservation properties: `convertAssets(convertShares(x)) <= x`.
- State machines with strict authorization guarantees.

## 2. Halmos Cheatcodes & Setup

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "halmos-cheatcodes/SymTest.sol";

contract VaultSymbolicTest is Test, SymTest {
    // Symbolic Variables
    // uint256 a = svm.createUint256("assets");
    // svm.assume(a > 0 && a < type(uint128).max);
}
```

## 3. Core Symbolic Invariant Templates

1. **No-Free-Minting Invariant:**
   $\forall a > 0 : \text{deposit}(a) \implies \text{sharesMinted} > 0$.
2. **Monotonic Value Invariant:**
   $\forall a, b : a \ge b \implies \text{convertToShares}(a) \ge \text{convertToShares}(b)$.
3. **Roundtrip Solvency Invariant:**
   $\forall a : \text{redeem}(\text{deposit}(a)) \le a$.

## 4. Execution & Violation Triage

Run via:
```bash
halmos --function check_invariant_
```

If Halmos finds a counterexample, it outputs the exact concrete assignment of symbolic variables that violates the assertion.
This concrete assignment is immediately transformed into an executable Foundry PoC in Phase 6.
