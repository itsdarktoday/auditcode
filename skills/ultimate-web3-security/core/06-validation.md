# Phases 6–7 — Exploit Validation & False-Positive Elimination

Goal: prove the attack executes and achieves material harm, or eliminate it with hard code-level evidence. Output: `{AUDIT_DIR}/validation.md`.

## 6.1 Executable Proof Engine (Mandatory for Critical / High)

Every candidate vulnerability rated Critical or High MUST undergo an executable proof attempt:

1. **Foundry Test Scaffolding (`skills/poc-builder/`):**
   - Pure logic / accounting bugs $\rightarrow$ Standalone Foundry unit test with minimal mocks.
   - External integration / state-dependent bugs $\rightarrow$ Mainnet-fork test pinned to a specific block number (`vm.createSelectFork(RPC, BLOCK)`).
2. **Canonical Exploit Sequence:**
   ```
   [Initial Baseline Snapshot]
      └── Record VictimBalanceBefore, AttackerBalanceBefore, TotalSupplyBefore
   [Step 1: Flash Loan / Capital Acquisition]
   [Step 2: State Priming / Parameter Distortion]
   [Step 3: Exploitation Call / Unauthorized State Delta]
   [Step 4: Profit Extraction / Collateral Drain]
   [Final Assertions]
      └── assertGt(AttackerBalanceAfter, AttackerBalanceBefore + ExpectedProfit)
      └── assertLt(VictimBalanceAfter, VictimBalanceBefore)
   ```
3. **Hostile Token & Callback Simulation Harnesses:**
   - Test against hostile ERC-20 variants: Fee-on-transfer (e.g. 2% fee on `transferFrom`), Rebasing tokens (positive/negative rebases), Zero-transfer reverting tokens, Blocklist-reverting tokens, Reentrant ERC-777/1155 callbacks on recipient.

## 6.2 Evidence-Tag Ladder & Ground Truth Authority

Every validated candidate is stamped with an authoritative evidence tag:

- `[POC-PASS]` (Score: 1.0) — Standalone executable Foundry test passes with explicit harm assertions.
- `[FORK-PASS]` (Score: 0.95) — Executable test passes on pinned mainnet fork against real contracts.
- `[MEDUSA-PASS]` (Score: 0.95) — Invariant fuzzer discovered concrete breaking sequence.
- `[NUMERIC-TRACE]` (Score: 0.85) — Complete, unbroken step-by-step mathematical trace with concrete numbers.
- `[CODE-TRACE]` (Score: 0.75) — Complete unbroken call path from entry point to storage corruption.
- `[SPECULATIVE]` (Score: 0.20) — Depends on unobservable off-chain conditions or future admin actions (Capped at LOW).

*Rule:* `[MOCK]` or `[SPECULATIVE]` evidence **cannot support a REFUTED verdict** for a valid code trace.

## 6.3 The 6-Dimension Devil's Advocate (DA) Pre-Gates

Run every candidate through these 6 strict falsification gates:

1. **K1 Impact Premise (WHO loses WHAT?):**
   - Name the specific victim cohort (e.g. "LPs in Pool X", "Borrowers who staked Token Y") and the financial magnitude of the loss.
   - If the finding only describes a mechanism (e.g. "function X can be called twice") with zero identifiable harm $\rightarrow$ **KILL / REJECT**.
2. **K2 Exact-Line Guard Interrupt:**
   - Read every require statement, modifier, custom error, and balance check on the call path.
   - Quote the EXACT line and file that prevents execution. If an exact line stops the exploit $\rightarrow$ **KILL**.
3. **K3 Speculative Defense Rejection:**
   - "The deployer would configure X properly", "Users will notice the front-run" $\rightarrow$ **INVALID DEFENSE (CLEARS GATE)**. Only code stops code.
4. **K4 Unprivileged Amplifier Requirement:**
   - If the attack requires a privileged role (Admin, Owner, Governance), reject UNLESS an unprivileged amplifier is proven:
     - Front-runnable setter / uninitialized state.
     - Lack of parameter bounds enabling permanent fund bricking.
     - Asymmetric formula enabling retroactive value extraction.
5. **K5 Dust & Looping Economics:**
   - If the extracted value is $\le \$10$ and cannot be looped $\rightarrow$ **CAP AT LOW**.
   - If the dust extraction can be looped within a single transaction / block to extract material profit $\rightarrow$ **SUSTAIN HIGH/CRITICAL**.
6. **K6 Self-Harm Only:**
   - If the only account that loses funds is the caller itself $\rightarrow$ **REJECT**.

## 6.4 Variant Exploration (Anti-Over-Filtering Rule)

**Before marking any candidate FALSE POSITIVE / REFUTED:**
The validator MUST test at least TWO relaxed variants of the attack:
1. **Timing Variant:** What if the attack is executed at block $T+1$, after an unbonding epoch, or immediately post-rebalance?
2. **Amount / Parameter Variant:** What if the input is 0, 1 wei, `type(uint256).max`, or an exotic token address?
3. **Ordering Variant:** What if the call order is reversed or interleaved with an external callback?

Only if ALL variants fail with concrete code-level guards is the candidate killed.

## 6.5 Promotion Criteria to Phase 10 Judge

A candidate proceeds to the Judge if it satisfies ANY of:
- **P1 Executable PoC:** Passes `[POC-PASS]` or `[FORK-PASS]`.
- **P2 Complete Trace:** Unbroken call path with real constants and no blocking guard.
- **P3 Multi-Lens Convergence:** Derived independently by $\ge 2$ lenses/agents.
- **P4 Unguarded Partial Path:** Reachable vulnerable logic with a named missing prerequisite (Judged at confidence $\le 75$).

## Output: `validation.md`

Structured file containing:
- Per candidate: Evidence Tag (`[POC-PASS]`, `[NUMERIC-TRACE]`, etc.).
- Exploit sequence, PoC file link (`test/Exploit.t.sol`), and exact `forge test` commands.
- DA Gate evaluation results (K1–K6).
- Documented kill ledger with exact line numbers for eliminated candidates.

## Exit Gate

- Every Critical/High candidate has an executable PoC attempt or unbroken numeric trace.
- All 6 DA pre-gates evaluated.
- Variant exploration executed for all contested candidates.
