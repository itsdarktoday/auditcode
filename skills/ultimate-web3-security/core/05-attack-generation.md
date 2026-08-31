# Phase 5 — Attack Generation (Hypothesis Engine)

Goal: transform raw leads and architectural models into rigorous, executable attack hypotheses. Answer: **"Can an adversary weaponize this defect into an exploit?"** Output: `{AUDIT_DIR}/hypotheses.md`.

## 5.1 Architecture-First Hypothesis Generation

Do not rely on static checklists. Generate attack paths from **what the code assumes that an adversary can break**:
- If code assumes *constant balance between calls* → test flash loans, donations, reentrancy callbacks.
- If code assumes *oracle price equals fair value* → test spot pool sandwiching, stale heartbeat windows, cross-block skew.
- If code assumes *caller is honest depositor* → test first-depositor inflation, zero-share mints, fee-on-transfer discrepancies.
- If code assumes *single transaction execution* → test Sui PTB batching, multicall `msg.value` reuse, cross-function reentrancy.
- If code assumes *transient storage is clean* → test re-entrant callbacks leaving dirty `TSTORE` state.

## 5.2 Multi-Stage Composable Attack Graph Engine

Synthesize complete, end-to-end multi-step transaction graphs:

```
[Phase A: Capital Setup] 
   └── Flash loan from Aave/Balancer/Uniswap OR borrow protocol tokens
[Phase B: State Priming / Invariant Distortion]
   └── Direct donation / spot price manipulation / transient storage priming / queue insertion
[Phase C: Trigger Exploitative Operation]
   └── Under-collateralized borrow / skewed share mint / zero-cost liquidation / reentrant drain
[Phase D: Unwinding & Settlement]
   └── Reverse state manipulation / repay flash loan / route extracted profits to attacker wallet
```

## 5.3 Economic Viability & Profitability Equations

For every financial hypothesis, compute the net exploitability equation:

$$\text{Net Extracted Profit} = \text{Gross Asset Extraction} - \text{Flash Loan Fees} (0.05\% - 0.09\%) - \text{DEX Swap Slippage} - \text{Total Gas Overhead}$$

- If $\text{Net Profit} > 0 \rightarrow$ **PROFITABLE EXPLOIT** (Critical/High).
- If $\text{Net Profit} \le 0$ but protocol/users suffer permanent capital loss $\rightarrow$ **INSOLVENCY / GRIEFING** (High/Medium).
- If loss is purely self-inflicted $\rightarrow$ **SELF-HARM (REJECT)**.
- If loss is non-loopable dust ($< \$10$) $\rightarrow$ **DUST (LOW/INFO)**.

## 5.4 Attack Hypothesis Schema

Every candidate hypothesis in `hypotheses.md` MUST fill this schema:

```markdown
### Hypothesis H-[ID]: [Title]
- **Target Component:** Contract.sol :: functionName()
- **Trigger:** (Caller type, entry point, parameters)
- **Preconditions:** (State requirements, token whitelist, oracle conditions)
- **Attack Steps (Concrete Graph):**
  1. Attacker flash-borrows $X amount of Token A.
  2. Attacker calls Contract.method1() causing state delta Δ1.
  3. Attacker triggers Contract.method2() which reads distorted state Δ1.
  4. Attacker extracts $Y amount of Token B.
  5. Attacker repays flash loan and pockets $Y - $X profit.
- **Violated Invariant:** INV-x ([Quote invariant text])
- **Impact Premise (WHO loses WHAT):** [e.g. Existing vault depositors lose 40% of their principal due to share dilution]
- **Capital & Tool Requirements:** [e.g. $50k flash loan, single-tx atomic]
- **Repeatability:** [One-shot / Looped continuous drain / Per-user]
- **Related Leads:** LEAD-xx
- **Validation Action:** VALIDATE NOW (P0) / VALIDATE LATER (P1) / DISCARD (with reason)
```

## 5.5 Prioritization & Triage

Rank all generated hypotheses by **Exploitability Index = Probability(Valid) × Severity × Verifiability**:
- **VALIDATE NOW:** Top candidates with complete multi-stage paths and identified financial harm.
- **VALIDATE LATER:** Candidates requiring deep external protocol simulation or fuzzing campaigns.
- **DISCARD:** Candidates killed by obvious, verified compiler or code-level guards (document the kill reason).

## Output: `hypotheses.md`

Structured file containing:
- Complete list of prioritized attack hypotheses.
- Step-by-step transaction graphs with parameter traces.
- Violated invariants and quantified impact premises.

## Exit Gate

- Every P0/P1 lead expanded into a concrete multi-stage hypothesis.
- Economic viability verified (WHO loses WHAT).
- Hypotheses triaged and ranked for Phase 6 validation.
