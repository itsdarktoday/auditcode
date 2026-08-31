# Phase 2 — Protocol Model

Goal: understand the architecture down to state variables; map asset flows, cross-contract data bindings, and formalize invariant contracts. Output: `{AUDIT_DIR}/protocol-model.md`.

## 2.1 Read Everything & Model from Code Truth

- Read ALL in-scope code before writing findings. Read tests, scripts, mocks, and deployment configs — they reveal developer assumptions and untested edges.
- Verify documentation claims against code reality. Mark every discrepancy as `⚠️ UNCLEAR - <what and why>`.
- Extract the protocol's native vocabulary (`sharePrice`, `borrowIndex`, `rewardDebt`, `unbondingWindow`) — audits must be argued in the protocol's own exact language.

## 2.2 Composable Money Map (Accounting-First Spine)

For every value-bearing flow, trace: **Source → Transit → Accounting Ledger → Destination**.

1. **Assets & Vaults Ledger Table:**
   - Every asset (native ETH, ERC-20, ERC-721, ERC-1155, LP tokens, synthetic claims).
   - Custody: Who holds the actual token balance? (Contract, Escrow, External Pool, Dynamic Field).
   - Ledger: Which mapping or variable tracks the internal entitlement?
   - Internal vs External Balance: Does the contract query `balanceOf(this)` or track an internal delta ledger? (Direct balance queries = vulnerable to donation/inflation).
2. **Tracked Totals & Symmetries:**
   - Every aggregate variable (`totalDeposits`, `totalDebt`, `totalSupply`, `totalShares`, `accRewardPerShare`).
   - Sibling symmetry: For every `+` write on deposit/mint, find the exact matching `-` write on withdraw/burn.
   - Branch symmetry: If an operation has multiple execution branches (e.g. early exit vs standard withdraw), ensure the aggregate is decremented in ALL branches.
3. **Fee Routing & Protocol Take:**
   - Fee rates, calculation formula, accrual point, and recipient address.
   - Check if fees dilute existing depositors or are minted as new claims.

## 2.3 Cross-Contract & Transient State Topology

- **Transient Storage Map (EIP-1153 `TSTORE`/`TLOAD`):**
  - Identify all transient storage slots (reentrancy flags, temporary caller contexts, transient allowances, swap delta accumulators).
  - Check cleanliness invariant: *Every transient slot set during execution MUST be reset to 0/clean before the transaction completes on all execution paths (including reverts in try/catch).*
- **Inter-Contract Dependency Graph:**
  - Map external oracle feeds, AMM pairs, yield strategy adapters, bridge endpoints.
  - For each dependency: Is it read-only, state-mutating, or callback-triggering?

## 2.4 State Machine & Lifecycle Transitions

For every lifecycle action (deposit, withdraw, borrow, repay, liquidate, swap, stake, claim, unbond, upgrade):
- **Preconditions:** Required caller state, balance thresholds, time/block maturity, pause status.
- **State Deltas:** Exact storage variables mutated in sequential order.
- **Postconditions:** Invariants that must hold after the state change.
- **Reversibility / Unwind:** What is the exact inverse path? Can a user always exit?

## 2.5 Ten Universal Invariant Classes (INV-x)

Extract 8–20 formal invariants with IDs `INV-x` covering these 10 universal classes:

1. **Conservation of Assets (Solvency):** `totalActualAssets >= sum(userEntitlements) + protocolReserves`
2. **Aggregate Integrity:** `trackedTotalX == Σ userBalancesX`
3. **Exchange Rate Monotonicity:** `sharePrice(t2) >= sharePrice(t1)` (absent explicit, documented losses/fees)
4. **Roundtrip Loss Bounds:** `withdraw(deposit(X)) <= X` and `withdraw(deposit(X)) >= X * (1 - maxDeclaredFee)`
5. **Directional Rounding Favoring Protocol:** Rounding MUST favor the system over the user (e.g. mint rounds down shares, redeem rounds down assets, debt rounds up).
6. **Health Factor Monotonicity:** Non-borrow actions (repay, deposit collateral) MUST strictly increase or preserve health factor.
7. **Debt Non-Erasure:** `userDebt` cannot decrease without corresponding `repay()` token transfer or liquidator collateral seizure.
8. **Clean State Termination:** Closing a position, unbonding, or full withdrawal MUST zero out related claim/debt pointers without residual locked dust.
9. **Read-Only Reentrancy Invariance:** View functions (`getPrice()`, `getUnderlying()`, `previewRedeem()`) MUST return clean post-state or revert during external callbacks.
10. **Transient Cleanliness:** All transient storage (`TSTORE`) slots return to zero before the root transaction ends.

## 2.6 Formal Numerical Stress-Testing Matrix

For all math formulas (interest accrual, share pricing, AMM curve, liquidation bonus):

| Variable / Parameter | Test Values | Expected Invariant Behavior |
|---|---|---|
| Zero Input | `amount = 0` | Must revert or result in 0 state delta; no free shares / no zero-transfer revert. |
| Minimum Dust | `amount = 1 wei` | Rounding must not result in 0-share mint or infinite exchange rate. |
| Maximum Bound | `amount = type(uint256).max` or `type(uint128).max` | No silent arithmetic overflow / no truncation on narrowing casts. |
| Decimal Mismatch | 6 decimals (USDC) vs 18 decimals (DAI/WETH) vs 27 decimals (Ray) | Scaling factors must be applied in correct order (`mulDiv` before divide). |
| Catastrophic Cancellation | `(A + B) - A` where `A >> B` | Precision of `B` must not be lost to zero. |
| Looped Rounding | 100 consecutive 1-wei operations | Accrued drift must be $\le 100$ wei, never compounding into protocol drain. |

## Output: `protocol-model.md`

Structured document containing:
- Protocol summary & native vocabulary index.
- Composable Money Map & Asset Custody Table.
- Transient & Cross-Contract State Graph.
- Core State Machine Transitions (forward and unwind paths).
- Complete Invariant Registry (`INV-01` to `INV-15+`).
- Numerical Stress-Test Traces for all mathematical formulas.

## Exit Gate

- Composable Money Map complete for all value flows.
- Transient storage usage cataloged and clean-state rules defined.
- $\ge 8$ formal invariants with IDs spanning solvency, accounting, and rounding.
- Numerical traces completed for non-trivial formulas.
