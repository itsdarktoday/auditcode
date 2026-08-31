# Phase 10 — Finding Judge

Goal: deliver final authoritative verdicts, recalibrated severities, and calibrated confidence scores for all candidate findings. Output: `{AUDIT_DIR}/judgments.md`.

You are an impartial security judge. You do not defend the codebase and do not manufacture vulnerabilities. You verify whether the claimed exploit fires end-to-end and delivers real-world impact.

## 10.1 The Five Sequential Judge Gates (Hard Execution Order)

Every candidate is evaluated sequentially. If a gate fails with concrete evidence, stop and assign verdict.

1. **Gate G1: Impact Premise Verification (WHO Loses WHAT):**
   - Must name the victim cohort and the concrete financial or operational harm (e.g. fund loss, unauthorized mint, permanent state bricking).
   - Mechanism descriptions without demonstrable harm $\rightarrow$ **FAIL (INFO / REJECT)**.
2. **Gate G2: Attack Execution Trace:**
   - Trace caller $\rightarrow$ state mutation $\rightarrow$ asset extraction.
   - Read every check, modifier, require statement, and assembly block on the path.
   - Fails ONLY when an exact code line provably interrupts the attack before harm (quote `file:line`).
   - `UNCERTAIN = ALLOWS` (an unproven guard is not a defense).
3. **Gate G3: Live Deployment Reachability:**
   - State must be reachable under production deployment parameters, token decimals, and oracle configs.
   - Structurally impossible or unreachable state $\rightarrow$ **FAIL (FALSE POSITIVE)**.
4. **Gate G4: Trigger & Privilege Boundaries:**
   - Permissionless trigger $\rightarrow$ **PASS**.
   - Privileged caller (Owner/Admin) $\rightarrow$ **REJECT** UNLESS an unprivileged amplifier is proven:
     - Front-runnable setter / uninitialized proxy.
     - Missing bounds enabling permanent fund lock.
     - Asymmetric formula enabling retroactive sweep.
     - Broken two-step ownership transfer.
5. **Gate G5: Materiality & Loopability:**
   - Non-loopable dust ($< \$10$) with no system degradation $\rightarrow$ **DEMOTE TO LOW**.
   - Self-harm only $\rightarrow$ **FAIL (REJECT)**.
   - Material direct or indirect asset loss $\rightarrow$ **CONFIRMED**.

## 10.2 Authoritative Verdict Taxonomy

| Verdict | Definition | Report Action |
|---|---|---|
| **VALID** | All 5 gates pass; verified by executable PoC `[POC-PASS]` or complete unbroken trace | Include in Findings |
| **LIKELY VALID** | Gates pass logically; minor trace step unverified but unguarded | Include in Findings |
| **CONTESTED** | Genuine ambiguity between lenses/reviewers; needs targeted human review | Include in Findings |
| **KNOWN / INTENDED** | Mechanism matches known-issues register or documented tradeoff | Move to Tradeoffs |
| **FALSE POSITIVE** | Exact code-level guard provably kills the exploit (cite `file:line`) | Validation Log |

## 10.3 Calibrated Severity Matrix (Immunefi / Top Audit Standard)

Severity is determined strictly by the **verified attack path and actual impact**, not the initial claim:

| Severity | Criteria (Permissionless Trigger) | Examples |
|---|---|---|
| **CRITICAL** | Direct, irreversible theft of protocol or user funds; protocol insolvency; total collateral drain; permanent lock of $>10\%$ TVL. | Flash loan price manipulation drain, share inflation vault theft, unauthorized `mint()`, missing init takeover. |
| **HIGH** | Conditional fund loss; theft requiring specific but reachable state; permanent bricking of core functions (deposits/withdrawals/liquidations); liquidation DoS affecting all users. | Bad debt accrual, un-liquidatable collateral positions, fee-on-transfer desync insolvency, read-only reentrancy oracle poisoning. |
| **MEDIUM** | Loss requiring strict prerequisites; admin actions with unprivileged amplifiers; per-user griefing; missing modifier on economic parameter setter; unhandled token edge cases without immediate drain. | Stale oracle without heartbeat, roundtrip precision leak, reentrancy on non-callback token, lack of slippage on protocol-owned swap. |
| **LOW** | Non-loopable dust/rounding errors; missing modifier on per-user preference setter; centralization risks without exploit path. | Small precision loss on 1 wei, gas griefing single user, missing event emissions. |
| **INFORMATIONAL** | Code hygiene, NatSpec doc mismatch, gas optimizations with zero security consequence. | Unused storage variable, outdated compiler pragma. |

## 10.4 Confidence Scoring (Labels, Never Removes)

Every VALID or LIKELY VALID finding appears in the report regardless of confidence score.

Start at **100**; deduct only for genuine weaknesses:
- Partial attack path (P4 promotion: named missing prerequisite) $\rightarrow -20$
- Relies on unverified external protocol / off-chain behavior $\rightarrow -10$
- Requires specific, complex setup conditions $\rightarrow -5$

**Bands:**
- $\ge 80$: High Confidence (PoC verified or airtight trace).
- $65–79$: Medium Confidence (Logical trace complete, minor mock assumptions).
- $40–64$: Low Confidence (Unguarded path with incomplete multi-hop trace).

## 10.5 Zero-Data-Loss Deduplication & Consolidation

1. **Root Cause Clustering:**
   - Cluster by `(contract, root_cause_mechanism, invariant)`.
   - If multiple functions suffer from the SAME missing check $\rightarrow$ Consolidate into ONE finding with a generalized title listing all affected functions.
2. **Mitigation Preservation (HARD RULE):**
   - If different agents or traces recommend distinct fixes $\rightarrow$ Output as **Option A** (e.g. Validate Input) and **Option B** (e.g. Restrict Caller). Never drop alternate fixes.
3. **Function Isolation:**
   - NEVER merge different root causes simply because they reside in the same function.

## 10.6 Completeness Assertion (Zero Silent Drops)

Before writing final judgments, execute and print:
`Completeness: N unique (Contract, function, mechanism) in leads, N covered by verdict or documented rejection.`

Every raw lead MUST be accounted for as VALID, LIKELY VALID, CONTESTED, KNOWN, or FALSE POSITIVE.

## Output: `judgments.md`

Structured file containing:
- Full verdict ledger for all candidates with gate evaluation logs.
- Recalibrated severities and confidence scores.
- Merged finding clusters with fix preservation.
- Completeness assertion statement.

## Exit Gate

- All candidates evaluated through Gates G1–G5.
- Zero silent drops (100% of leads accounted for).
- Confidence scores and recalibrated severities assigned.
