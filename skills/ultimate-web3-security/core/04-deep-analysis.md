# Phase 4 — Deep Analysis

Goal: discover high-severity leads through manual reasoning, protocol archetype engines, 14 core analysis lenses, static analyzers, and invariant fuzzing. Output: `{AUDIT_DIR}/leads.md`.

## 4.1 Auditing Discipline & Multi-Pass Protocol

- **Function-by-Function Interrogation:** Work methodically down the ranked attack surface. Never skim or jump across files without establishing local state invariants.
- **Three-Pass Contract Interrogation:**
  1. **Pass 1 — Data Flow & State Mutation:** Map what moves, which storage slots are written, where external calls occur, and how aggregates update.
  2. **Pass 2 — Adversarial Inversion (Skeptic):** For every check and modifier, ask: *How do I bypass or make this condition evaluate to true? What dirty state slips past?*
  3. **Pass 3 — Cross-Contract Composition:** How does this function behave when invoked in the middle of an external callback, re-entered via a view function, or batched with flash loans?
- **Saturation Mandate:** When a vulnerability pattern is discovered in one function, **immediately scan the entire repository** for the identical pattern by code shape, variable name, and call flow. Missing an echo instance is an audit failure.

## 4.2 The 8-Level Manual Reasoning Model

Execute sequentially on every critical function:

1. **Code (Literal Execution):** What does the code literally execute? (Feynman test: explain in plain English. Fuzziness = hidden assumption = bug).
2. **State Deltas:** Exactly which storage variables and transient slots mutate? In what order?
3. **Protocol Rationale:** Why was this written this way? What business intent does it serve?
4. **Invariants (INV-x):** Which formal invariant does this touch? Can a specific input violate it?
5. **Attacker Capabilities:** What parameter, balance, timing, or external state does the adversary control?
6. **Economics (Impact Premise):** Can this violation extract profit or inflict unrecoverable loss? **WHO loses WHAT?**
7. **Compositional Amplification:** Can flash loans, callbacks, multicall batches, or oracle shifts amplify the loss?
8. **Proof Construction:** Can this be proven with concrete numbers or an executable PoC?

## 4.3 Protocol Archetype Specialized Engines

Activate the specialized engine matching the target's archetype:

### A. Lending / CDP / Money Markets
- **Interest Rate Discontinuities:** Kink models with steep slopes; utilization calculation front-running.
- **Liquidation Cascades & Bad Debt:** Can liquidations be griefed via gas exhaustion, blacklisted collateral, or dust positions? Does partial liquidation leave un-liquidatable bad debt?
- **Health Factor Post-Liquidation Asymmetry:** Does seizing collateral at a fixed discount make the borrower's health factor *worse* than before liquidation?
- **Oracle Heartbeats & L2 Sequencer:** What happens during oracle feed delays or when the L2 sequencer restarts without a grace period?

### B. AMMs & Decentralized Exchanges
- **Concentrated Liquidity & Tick Rounding:** Rounding drift across tick transitions; fee growth global calculation underflows.
- **Stableswap Invariants & Root Finding:** Newton-Raphson non-convergence on extreme imbalances; virtual price inflation.
- **Uniswap v4 & Custom Hooks:** Can an attacker spoof hook return deltas? Is beforeSwap/afterSwap lifecycle reentrancy protected? Can hook transient storage leak into sibling swaps?

### C. Yield Vaults & ERC-4626 Tokenized Vaults
- **Share Inflation & First Depositor:** Is direct token donation to an empty vault protected by dead shares / virtual offset?
- **Symmetry Violation in ERC-4626:** Does `convertToShares(assets)` match `previewDeposit(assets)`? Does rounding direction strictly favor the vault (`mulDiv(..., Math.Rounding.Down)`)?
- **Harvest Sandwiching:** Can an attacker deposit immediately before `harvest()` and withdraw immediately after, stealing yield without time exposure?

### D. Liquid Staking (LST) & Restaking (LRT)
- **Slashing Propagation Delay:** Can users frontrun a slashing event on the beacon chain / AVS by redeeming LRT shares at the pre-slash exchange rate?
- **Unbonding Queue Manipulation:** Can an attacker grief the withdrawal queue or withdraw ahead of earlier depositors?

### E. Perpetuals & Synthetic Derivatives
- **Skew & Funding Rate Arbitrage:** Can an attacker manipulate the index/mark price spread to extract funding payments risk-free?
- **Settlement Latency:** Is there a delay between order placement and keeper execution? Can price movement between check and fill be exploited?
- **ADL (Auto-Deleveraging) Priority:** Can unprofitable positions manipulate the ADL queue to offload bad debt onto profitable traders?

### F. Cross-Chain Bridges & Relayers
- **Payload Ambiguity & Nonce Replay:** Can a message payload hash collide with another domain? Are nonces consumed on destination *before* execution?
- **Gas Limit Griefing:** Can an attacker send a message with insufficient gas for destination execution, trapping source assets in bridge escrow?

### G. Account Abstraction (ERC-4337)
- **Validation Rule Breaches:** Does `validateUserOp` access forbidden storage (out-of-tree accounts) causing bundler simulation divergence?
- **Paymaster Drain:** Can an attacker construct transactions that pass paymaster validation but revert execution, draining the paymaster's gas deposit?

## 4.4 Fourteen Core Analysis Lenses

1. **L1 Accounting Drift:** Missing, one-sided, mistimed, or wrong-party writes to aggregate balances.
2. **L2 Access Control & Init:** Privilege escalation, missing modifiers, uninitialized logic contracts, UUPS auth absence.
3. **L3 Rounding, Precision & Math:** Decimal conversion errors (6 vs 18 vs 27), integer division truncation, catastrophic cancellation.
4. **L4 Oracle Manipulation & Staleness:** Spot price manipulation, stale rounds without heartbeat, unhandled zero/reverting feeds.
5. **L5 Liquidation Incentives & Solvency:** Unprofitable liquidations, bad debt socialization failures, self-liquidation arbitrage.
6. **L6 Signatures & Permits:** Missing `chainId` in domain, signature malleability, permit front-running, cross-contract replay.
7. **L7 Reentrancy (Classic & Read-Only):** State reads after external calls, Balancer-style view reentrancy, hook callbacks.
8. **L8 Transient Storage (EIP-1153 `TSTORE`/`TLOAD`):** Dirty transient storage slots, cross-call reentrancy in the same tx, missing cleanup in try/catch.
9. **L9 Upgradeability & Storage Layout:** Storage slot collisions, missing storage gaps, implementation `selfdestruct`/destruction.
10. **L10 Governance & Voting:** Flash-loan voting power, snapshot timing desyncs, timelock bypasses.
11. **L11 DoS & State Bloat:** Unbounded loops over user-pushed arrays, push-over-pull token transfers, gas griefing.
12. **L12 Cross-Chain Synchronization:** Message ordering, relayer trust assumptions, replay protection across forks.
13. **L13 Composability & External Integrations:** Fee-on-transfer, rebasing, blacklisting, non-standard ERC-20 return values.
14. **L14 Compiler, Assembly & Low-Level Nuances:** Free memory pointer corruption (`0x40`), dirty upper bits in assembly, 63/64th gas forwarding rule.

## 4.5 Static Tooling Integration

Run available static analyzers to generate raw candidate leads:
- Slither (`slither . --exclude-dependencies`) → Broad structural checks.
- Semgrep (`semgrep --config {SKILL_DIR}/tools/semgrep.md`) → Precision patterns.
- Aderyn (`aderyn .`) → Rust/Solidity vulnerability patterns.
- CodeQL → Data-flow taint analysis.

*Rule:* Every tool alert is a **LEAD** — it MUST be verified through the manual reasoning model before promotion.

## 4.6 Invariant Fuzzing & Dynamic Harnesses

- In `--deep` mode: Translate extracted `INV-x` properties into Echidna/Medusa/Foundry fuzz test harnesses (see `{SKILL_DIR}/skills/fuzz-harness/SKILL.md`).
- Run bounded campaigns (15–30 min) targeting high-risk accounting and math functions.
- Fuzzer violations immediately feed into `leads.md`.

## Output: `leads.md`

Structured list of leads:
- Lead ID (`LEAD-01`, `LEAD-02`...)
- Target Contract, Function, and Line Numbers
- Core Mechanism & Violated Invariant (`INV-x`)
- Origin (Manual Lens L1-L14 / Tool Alert / Fuzzing Violation)
- Preliminary Priority (P0 / P1 / P2)
- Open Verification Questions

## Exit Gate

- All ranked attack surfaces interrogated with applicable archetype engines.
- All 14 lenses applied to relevant contract paths.
- Saturation scan performed for every identified bug pattern.
- Every lead mapped to a concrete mechanism and invariant.
