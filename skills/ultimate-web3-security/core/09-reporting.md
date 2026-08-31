# Phase 11 — Final Report

Goal: synthesize all verified findings, reproducible PoCs, and actionable diff mitigations into an elite, executive-ready security audit report. Output: `{AUDIT_DIR}/report.md` (and optionally `{TARGET}/SECURITY_REPORT.md`).

## 11.1 Finding Schema (Immunefi / Top Audit Standard)

Every validated finding MUST use this exact structure (use `templates/finding.md`):

```markdown
### [FINDING-01] [TITLE CARRYING ROOT CAUSE AND SECURITY CONSEQUENCE]

- **Severity:** [CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL]
- **Evidence Level:** [`[POC-PASS]` / `[FORK-PASS]` / `[NUMERIC-TRACE]` / `[CODE-TRACE]`]
- **Confidence Score:** [e.g. High (95/100)]
- **Affected Components:** `Contract.sol::functionName()` (Lines L120-L145)
- **Target Invariant Broken:** INV-x ([Quote invariant statement])

#### 1. Root Cause
[Concise 1-2 sentence explanation of the code-level defect in the protocol's native vocabulary.]

#### 2. Attack Path & Execution Trace
[Step-by-step transaction walkthrough: Caller -> Inputs -> State Delta -> Asset Drain.]
1. Attacker calls `deposit()` with 1 wei.
2. Attacker executes direct transfer of 100 tokens to the vault address.
3. Victim calls `deposit()` with 50 tokens, receiving 0 shares due to rounding down.
4. Attacker calls `redeem()` with 1 share, extracting all 150 tokens.

#### 3. Impact & Financial Consequence (WHO loses WHAT)
[Quantify the concrete loss: "100% loss of victim's deposited principal; protocol insolvency of $X."]

#### 4. Proof of Concept & Reproducibility
- **PoC File:** `{AUDIT_DIR}/poc/finding-01/Exploit.t.sol`
- **Execution Command:**
  ```bash
  forge test --match-test test_exploit_drain -vvvv --fork-url $ETH_RPC_URL --fork-block-number 19400000
  ```

#### 5. Why Existing Checks Do Not Prevent It
[Explain why existing modifiers, require statements, or compiler guards fail to block this path.]

#### 6. Recommended Mitigation (Actionable Code Diff)
```diff
- uint256 shares = (assets * totalShares) / totalAssets;
+ uint256 shares = (assets * (totalShares + 1e3)) / (totalAssets + 1);
```
*(If distinct fixes were derived, present as **Option A** and **Option B**).*
```

## 11.2 Report Structure (Executive to Technical)

1. **Executive Summary:**
   - Protocol overview, architectural archetype, and total nSLOC audited.
   - Findings summary table categorized by severity and evidence level.
   - Core systemic risk themes.
2. **Scope & Methodology:**
   - Evaluated commit hash, chain targets, and tools executed.
   - Invariant model summary (`INV-01` to `INV-15`).
   - Effort mode (`--deep`, `--standard`).
3. **Validated Vulnerabilities:**
   - Critical, High, and Medium findings in full template format.
4. **Design Tradeoffs & Documented Centralization:**
   - Privileged roles by design (timelock configurations, emergency pause powers).
5. **High-Signal Leads (For Future Exploration):**
   - Unverified leads with explicitly stated open questions.
6. **Validation Log (Eliminated Candidates):**
   - All killed hypotheses with exact killing code lines (`file:line`).
7. **Completeness & Integrity Assertion:**
   - `Completeness: N unique leads generated, N accounted for with zero silent drops.`

## 11.3 Honesty Rules & Anti-Manufacturing Discipline

- **No Speculative or Manufactured Findings:** "No valid vulnerability found" is a valid and successful outcome if accompanied by a complete validation log and coverage receipts.
- **Never Report:** Compiler warnings, linter formatting, gas micro-optimizations dressed as bugs, or admin privileges matching documented design without unprivileged amplifiers.
- Every severity rating MUST be justified directly by the verified attack path.

## Output: `report.md`

Save complete report to `{AUDIT_DIR}/report.md`.

## Exit Gate

- Every validated finding formatted with complete evidence tags, PoC commands, and diffs.
- Completeness assertion printed.
- Honesty rules verified.
