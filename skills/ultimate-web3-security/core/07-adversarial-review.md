# Phases 8–9 — Adversarial Review & Second Opinion

Goal: subject every surviving candidate to hostile disproof from an independent perspective. Output: `{AUDIT_DIR}/adversarial-review.md`.

## 8.1 The Skeptic Inversion Mandate

The adversarial reviewer is structurally opposed to the finding's validity. The objective is: **"DISPROVE this vulnerability. Prove why this attack cannot succeed in production."**

Audit across 5 inversion dimensions:
1. **Precondition Reachability:** Can the required state actually occur in a live deployment? (Constructor parameters, proxy initialization, deployment scripts, active token lists).
2. **Hidden Code-Level Defenses:** Look for implicit guards:
   - Upstream bounds in parent contracts.
   - Solidity $\ge 0.8$ arithmetic underflow/overflow reverts (e.g. recursive decrement reverting on second step).
   - SafeERC20 / nonReentrant modifiers on inherited paths.
   - Transient storage (`TSTORE`) resets in sibling internal calls.
3. **Economic Self-Inconsistency:**
   - Does the attack cost more in gas + flash-loan fees (0.09%) + DEX slippage than the extracted value?
   - Is the extraction MEV-sandwichable by public searchers before the attacker pockets profit?
4. **Documented Design Tradeoffs (Accepted Intent):**
   - Is this explicit protocol behavior documented in whitepapers/README? (Cite document and line).
5. **Attack-Your-Own-PoC (Hostile Fuzzing):**
   - Stress-test the PoC: Change caller address, randomize deposit amounts, execute at varied block timestamps (`vm.warp`), test with 6-decimal and 18-decimal token configurations.
   - *If the PoC survives hostile perturbation, confidence increases to 95%+.*

## 8.2 Committed Invariant Defenses (Falsifiable Claims)

When the skeptic asserts that an attack is blocked, it MUST commit that defense as a **falsifiable invariant assertion**:
- `[CI-1: CONSERVATION]` — Total protocol assets cannot decrease below total user liabilities.
- `[CI-2: REQUESTED_EQ_DELIVERED]` — The received token amount matches the requested parameter.
- `[CI-3: APPROVE_EQ_SPEND]` — Allowances cannot be spent without approval decrement.
- `[CI-4: NO_REVERT_AT_BOUNDARY]` — Extreme values (0, 1 wei, max) do not cause unexpected reverts.
- `[CI-5: ROUNDTRIP]` — Immediate deposit and withdraw is strictly non-profitable.
- `[CI-6: FRESHNESS]` — Oracle readings are guaranteed fresh within the heartbeat window.

*Rule:* If the skeptic claims a defense but cannot express it as an invariant or quote the exact code line $\rightarrow$ **Skeptic disproof FAILS; finding holds.**

## 8.3 Blind Second Opinion Protocol

For each surviving candidate, obtain an independent fresh derivation:
- **Blind Context Dispatch:** Provide the second reviewer ONLY the code region, contract name, and the formal invariant claim (`INV-x`). **NEVER forward the original attacker trace, finding description, or prior agent's verdict.**
- **Reviewer Contract:**
  1. Derive own attack path or defense from clean code.
  2. Return verdict: `CONFIRM` | `KILL` | `UNKNOWN`.
  3. If `KILL`, cite the EXACT line/guard that stops the exploit.
- **Conflict Resolution Matrix:**
  - `CONFIRM` + `CONFIRM` $\rightarrow$ VALID (Confidence: High 90–100).
  - `CONFIRM` + `KILL` $\rightarrow$ Candidate sent back to Phase 6 validation to test against the cited killing line.
  - `KILL` without code-level line proof $\rightarrow$ Burden of proof unmet; `CONFIRM` wins.

## Output: `adversarial-review.md`

Structured file containing:
- Per candidate: Inversion audit results across the 5 dimensions.
- Committed Invariant Defense evaluations (`[CI-x]`).
- Hostile PoC stress-test execution results.
- Blind Second Opinion verdicts and conflict resolution notes.

## Exit Gate

- Every candidate audited under the Skeptic Inversion Mandate.
- PoCs hostilely tested against parameter perturbations.
- Blind Second Opinion recorded for all Critical/High/Medium candidates.
