---
name: fuzz-harness
description: Invariant-driven stateful fuzzing sub-skill for the ultimate-web3-security pipeline. Transforms formal protocol invariants into executable Echidna, Medusa, and Foundry invariant test suites. Loaded in Phase 4/6 for dynamic state exploration.
---

# Fuzz Harness (Invariant Testing with Medusa / Echidna / Foundry)

Turns formal invariants (`INV-01` to `INV-15`) into automated, stateful property tests that discover deep multi-transaction edge cases human auditors miss.

## 1. When to Deploy Invariant Fuzzing

- Complex accounting & share conversion math (`totalAssets == Σ userBalances`, exchange rate monotonicity).
- State machines with multiple user roles, unbonding queues, or asynchronous settlement steps.
- Liquidation logic with dynamic collateral prices and changing fee structures.

## 2. Invariant Property Definitions (The 5 Core Classes)

Translate `INV-x` from Phase 2 into executable boolean properties in `Properties.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Handlers} from "./Handlers.sol";

contract Properties is Handlers {
    // 1. Solvency Invariant: Actual tokens must back or exceed total tracked claims
    function property_solvency() public view returns (bool) {
        return asset.balanceOf(address(target)) >= target.totalTrackedAssets();
    }

    // 2. Aggregate Equivalence: Tracked total must equal the sum of all individual user balances
    function property_aggregate_integrity() public view returns (bool) {
        return target.totalShares() == ghost_sumUserShares;
    }

    // 3. Monotonic Share Price: Share price should never decrease without explicit realized losses
    function property_share_price_non_decreasing() public view returns (bool) {
        uint256 currentPrice = target.convertToAssets(1e18);
        return currentPrice >= ghost_lastSharePrice;
    }

    // 4. Non-Zero Division / No Revert on Valid Range
    function property_no_unexpected_arithmetic_revert() public view returns (bool) {
        return !ghost_hasArithmeticReverted;
    }

    // 5. Transient Cleanliness: All transient storage slots reset to zero
    function property_transient_cleanliness() public view returns (bool) {
        return target.transientLock() == 0;
    }
}
```

## 3. Stateful Handler Architecture & Ghost Variables

Create handlers in `test/fuzz/handlers/TargetHandler.sol` that track ground truth via ghost variables:

- `ghost_sumUserShares`: Incremented on mint, decremented on redeem.
- `ghost_totalDeposited`: Tracked net token deposits across all fuzz actors.
- **Actor Boundaries:** Restrict caller addresses to an indexed actor array (`address[3] actors = [0x10000, 0x20000, 0x30000]`).
- **Semantic Value Clamping:** Use `bound(amount, MIN, MAX)` to avoid unrealistic 0-token transfers or `type(uint256).max` overflow noise while strictly exploring boundary values ($0$, $1$ wei, $\text{depositMax}$).

## 4. Execution Tools & Automation Scripts

Run via `{SKILL_DIR}/scripts/`:
- `ensure_foundry.sh <ROOT>` $\rightarrow$ Verify Forge toolchain.
- `generate_suite.js <ROOT>` $\rightarrow$ Auto-scaffold `test/fuzz/` structure.
- `setup_fuzz_profile.sh <ROOT>` $\rightarrow$ Configure `[profile.fuzz]` with `via_ir = false` to maximize code coverage in Medusa/Echidna.
- `run_medusa.js <ROOT>` / `run_echidna.js <ROOT>` $\rightarrow$ Execute campaigns with plateau detection and coverage tracking.

## 5. Violation Triage & Reproduction

When a fuzzer breaks a property:
1. **Extract Minimal Call Sequence:** Identify the exact sequence of transactions (e.g. `deposit(1) -> donate(100e18) -> deposit(50e18) -> redeem(1)`).
2. **Reproduce in Standalone Unit Test:** Port the sequence directly to `test/Exploit_Repro.t.sol` using Foundry.
3. **Falsification Check:** Confirm whether the violation is a genuine protocol vulnerability or a harness artifact (e.g. unrealistic mock behavior or unconstrained ghost variable).
4. **Feed to Phase 5:** Real violations immediately feed into `leads.md` as P0 leads.

## Output

Artifacts in `{AUDIT_DIR}/fuzz/`:
- `Harness/` (Base, Handlers, Properties).
- `PROPERTIES.md` — Mapping of `INV-x` to code property functions.
- `VIOLATIONS.md` — Triaged breaking sequences and reproduction traces.

