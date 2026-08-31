# Plamen — Validation-Methodology Extraction Report

**Repo:** `/home/nishan/ultimate-web3-security/sources/plamen` (v2.2.4, MIT)
**Type:** Autonomous multi-agent Web3 audit orchestrator (Claude Code + OpenAI Codex backends, Python driver) for EVM/Solana/Aptos/Sui/Soroban/DAML smart contracts and L1 Go/Rust node clients.
**Primary files studied:** `rules/phase4-confidence-scoring.md`, `rules/phase5-poc-execution.md`, `rules/phase4c-chain-prompt.md`, `rules/finding-output-format.md`, `rules/report-template.md`, `prompts/evm/generic-security-rules.md`, `prompts/shared/v2/phase{3,4a5,4e,5,6d,6e}*.md`, `agents/security-{analyzer,verifier}.md`, `agents/depth-*.md`, `docs/l1-mode/severity-matrix.md`, `skills/audit-prep/*`, `agents/skills/evm/verification-protocol/SKILL.md`.

---

## 1. Contribution summary

Plamen is the most complete *pipeline-level* validation methodology in this corpus: it treats audit truth-production as a manufacturing line in which a Python driver owns runtime policy (checkpoints, gate checks, retry-once-then-degrade, disk-marker completion inference) and the LLM owns methodology ("Python does NOT compose subagent prompts… The Python driver owns **runtime policy**" — `rules/orchestrator-rules.md`). Its durable contribution is a closed, machine-checkable vocabulary for *evidence* and *verdicts*: findings move through breadth (amplify-only discovery) → depth (real-constant, boundary-value analysis) → chain (precondition/postcondition composition) → verification (harm-asserting PoCs, re-executed mechanically by the driver, which stamps the authoritative evidence tag) → skeptic-judge adversarial re-verification (Thorough mode) → semantic dedup (zero-data-loss) → material-harm body disposition (BODY/APPENDIX, recall-safe default BODY) → report assembly with hard hygiene gates (no internal IDs, count match, no silent drops). Where most competitor tools stop at "write a PoC," Plamen adds: a PoC testability ledger with a *closed taxonomy* of skip reasons audited by the driver; an "impact premise verification" gate distinguishing mechanism tests from harm tests; an evidence-source ladder in which only `[POC-PASS]`/`[MEDUSA-PASS]`/`[PROD-*]` support CONFIRMED-as-ground-truth and mock/unverified evidence *cannot* support REFUTED; a 4-axis numeric confidence model routing further depth spend; and adversarial-inversion phases (exploration skeptic is additive-only; skeptic-judge is disproof-oriented) that are explicitly forbidden from deleting findings. The same discipline is ported to L1 infrastructure auditing via a dedicated Immunefi-v2.3-aligned severity matrix and differential/conformance evidence tags.

---

## 2. Most valuable techniques and gates

### 2.1 Severity taxonomy and rubric (exact bands)

**A. Smart-contract matrix — `rules/report-template.md` § "Severity Matrix (Impact × Likelihood)":**

| | Likelihood: High (no prerequisites, anyone) | Likelihood: Medium (specific conditions) | Likelihood: Low (unlikely/complex setup) |
|---|---|---|---|
| Impact: High (direct fund loss/permanent lock) | **Critical** | **High** | **Medium** |
| Impact: Medium (conditional fund loss, protocol breakage) | **High** | **Medium** | **Medium** |
| Impact: Low (broken views, incorrect data, non-fund) | **Medium** | **Low** | **Low** |
| Impact: Informational (quality, style, unused code) | **Informational** | **Informational** | **Informational** |

Downgrade modifiers (post-lookup): "On-chain-only exploit (no UI/off-chain path) → −1 tier" (with an explicit exception when impact crosses the on-chain/off-chain boundary, e.g. corrupted events breaking indexers); "View-function-only impact → cap at Medium"; "Attack path requires fully-trusted actor… → −1 tier (floor: Informational). This applies ONLY to `FULLY_TRUSTED` actors (governance multisig, DAO, timelock). Semi-trusted actors (admin, operator, keeper, oracle) are NOT downgraded here." Every adjusted finding must carry the note *"Severity adjusted - attack requires {actor} to violate stated trust assumption: {assumption}."*


**B. L1 matrix — `docs/l1-mode/severity-matrix.md`** (Immunefi v2.3-aligned): Critical = "Network cannot confirm new transactions; unintended chain split; direct loss of user funds via protocol-level mechanism; permanent freeze of >10% of staked funds; consensus failure leading to unrecoverable state"; High = network-wide DoS, temporary fund freeze/slashing, reorg enabler, light-client bypass, "node crash reachable by any peer"; Medium = single-node DoS, in-node privilege escalation, finality delay; Low = resource inefficiency, "bugs requiring a trusted position"; Informational = hygiene/docs. Likelihood tiers are permissionless / specific-conditions / complex-setup. Eight calibration adjustments encode real-world outcomes, e.g.:

> "1. **Eclipse attacks default to Medium**, upgraded to High only if the attacker can reach ≥30% of nodes cheaply."
> "3. **RPC crash without chain impact is High only if** the affected client has ≥25% market share."
> "5. **Single-client consensus violations** (where other clients continue validating) are High, not Critical."
> "7. **Latent dead-code findings are capped at High**… A latent finding cannot be Critical unless a PoC demonstrates a realistic activation path within the audited commit."
> "8. **Bundle-incomplete findings are PARTIAL by default.** A finding that flags one missing field in a multi-field validation bundle… MUST cite the §3d Validation-Bundle artifact OR be marked PARTIAL until the full enumeration is performed."

Every L1 finding must carry a **Severity rationale** citing "Impact: [cell] / Likelihood: [cell] / Modifiers: [list] = [tier]" — "This makes grading auditable and makes disagreements mechanically resolvable in review."

**C. Root-cause consolidation — `rules/report-template.md`:** "Findings that share the same root cause MUST be consolidated into a single finding. Same **variable** does not mean same root cause - if findings require **different fixes**, they are separate root causes." Merged findings "Use the **highest severity** from the matrix across all sub-impacts" and list all locations in a table.

### 2.2 Confidence gates (numeric thresholds)

**A. 4-axis composite — `rules/phase4-confidence-scoring.md`:**

- Axes: **Evidence** ("Best evidence tag: [PROD-ONCHAIN]=1.0, [PROD-SOURCE]=0.9, [PROD-FORK]=0.9, [MEDUSA-PASS]=1.0, [CODE]=0.8, [DOC]=0.4, [MOCK]=0.2, [EXT-UNV]=0.1"), **Consensus** ("(agents that flagged same root cause) / (agents whose domain covers this location). If only 1 agent's domain covers the location → Consensus = 1.0 if that agent found it. **Specialized agent bonus**: +0.2 when finding discovered by an agent instantiated from a Required skill template (capped at 1.0)"), **Analysis Quality** (depth agents: 0 depth-evidence tags=0.1, 1 tag=0.4, 2 tags=0.7, 3+ tags=1.0; others: completed-steps ratio), **RAG Match** ("Score = validate_hypothesis result / 10. If RAG Sweep tool call failed for a finding: 0.3 (floor)").
- Formula: `composite = Evidence × 0.25 + Consensus × 0.25 + Analysis_Quality × 0.3 + RAG_Match × 0.2`.
- Routing thresholds: "≥ 0.7 → **CONFIDENT** | No more depth needed"; "0.4–0.7 → **UNCERTAIN** | Spawn targeted depth agent"; "< 0.4 → **LOW CONFIDENCE** | Spawn depth agent + force production verification + RAG deep search".
- Budget allocation: `spawn_priority = (1 - composite) * severity_weight` with weights "Critical | 4, High | 3, Medium | 2, Low | 1, Info | 0.5" — "This ensures a Critical finding at 0.5 confidence (priority = 0.5 × 4 = 2.0) gets depth before a Low finding at 0.4 confidence."
- Convergence: "**Hard iteration cap**: Maximum 3 iterations"; dynamic spawn caps (`hard_cap = 20 + niche_overflow + thorough_bonus`).

**B. Verdict-gate asymmetry (the highest-value single rule, repeated in every depth agent and verifier):**

> "**Confidence Gate**: Uncertain? → CONTESTED, not REFUTED. Only REFUTED if defense proven with production evidence" (`agents/depth-*.md`, `agents/security-verifier.md`)
> "**Enabler Search**: Before REFUTED, ask 'Does ANY other finding enable this?'"

Combined with the mock-evidence rule (`agents/skills/evm/verification-protocol/SKILL.md`): "**AUTOMATIC OVERRIDE**: If ANY evidence supporting REFUTED has tag [MOCK] or [EXT-UNV]: - CANNOT return REFUTED - MUST return CONTESTED - Triggers production verification." And CONTESTED is escalatory, not terminal: "CONTESTED findings get same verification priority as HIGH severity" (`generic-security-rules.md`).

**C. RAG sweep fallback chain — `rules/phase4-confidence-scoring.md`:** if MCP fails, try `get_similar_findings` → `get_common_vulnerabilities` → WebSearch `site:solodit.xyz` → "record [RAG: ALL_TOOLS_FAILED] and score = 0.3"; "If the FIRST MCP call fails with a schema/API error, assume ALL MCP calls will fail" (no N×timeout retries); "If MCP tools SUCCEED but return 0 supporting examples AND 0 solodit matches for the first 3 findings, treat this as 'empty database'" — a genuinely reusable anti-stall gate.

### 2.3 Verification workflow (verifier agent logic and PoC requirements)

**A. Harm-assertion hard gate — `rules/phase5-poc-execution.md` § "Impact Premise Verification (MANDATORY — HARD GATE)":**

> "Before writing the PoC, identify the finding's claimed HARM in one sentence — not the mechanism, but the consequence. The PoC MUST assert the HARM directly. A PoC that only proves a function can be called, a state can be reached, or a path exists is NOT a `[POC-PASS]` — it is a mechanism test, not a harm test."

Mechanism tests (insufficient): "startLiquidation succeeds while market is active", "parameter can be set to zero", "reentrancy callback is triggered". Harm tests (required): "claimant receives 15% less than their pro-rata share after attack sequence", "attacker extracts 1.5x their fair share via reentrancy before guard triggers". The same standard feeds the **Material Harm** finding field (`rules/finding-output-format.md`): "State WHO loses WHAT… A finding whose only stated harm is a MECHANISM… without a concrete consequence is NOT a body finding: cap it at Informational and route it to the Quality Observations megasection."

**B. Evidence-tag ladder and truth monopoly:**

> "`[POC-PASS]` is the only tag that supports CONFIRMED as ground truth. `[POC-FAIL]` defaults to the attack not working - to override, demonstrate the failure is test setup error, not a defense. `[CODE-TRACE]` caps at CONTESTED unless the trace is complete with real constants."

`[MEDUSA-PASS]` is "mechanical proof (same weight as `[POC-PASS]`)". Report-side, the driver pre-computes a verification-status legend (`rules/report-template.md`): `VERIFIED` = "Verdict CONFIRMED **and** effective best evidence is proof-grade"; `CONFIRMED` = verdict confirmed with only `[CODE-TRACE]` ("A real confirmed finding — **NOT** `UNVERIFIED`"); `CONTESTED`; `UNVERIFIED` = "Refuted / false-positive / none".

**C. PoC Testability Ledger + closed skip taxonomy — `rules/phase5-poc-execution.md`:** every verifier output carries `PoC Class: <unit|property|integration|structural>`, `Attempted: YES/NO`, `PoC Not Attempted Because:` with only `NO_BUILD_ENVIRONMENT | EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS | DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL | PURE_SPEC_OR_DOCS_ONLY | STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` allowed — and for unit/property rows in a buildable repo, "a local executable attempt is mandatory"; the structural skip code "is NOT an allowed skip reason for `unit` or `property` rows". A Material-Harm finding may skip only on a named blocker from the closed force-gate taxonomy (`FULLY_TRUSTED_DESIGN`, `DEPLOY_OR_TX_ORDERING`, `EXTERNAL_DEP_NO_FORK`, `LIVE_ARTIFACT_REQUIRED`, `SPEC_DOCS_NO_STATE_DELTA`, or a REFUTED verdict), "with a CODE-GROUNDED justification the driver will check". The driver mechanically audits skip validity (`phase5-verification-sc.md`): "`NO_BUILD_ENVIRONMENT` is invalid when the build succeeded; `EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS` is invalid when the dependency can be mocked"; "**For Critical/High/Medium `unit`/`property` rows, 'needs a mock', 'complex setup', 'disproportionate for this severity'… are NOT valid blockers.**"

**D. Driver-owned evidence tag / integrity downgrade — `phase5-verification-sc.md`:**

> "A `[POC-PASS]` you write that is NOT backed by a test the executor can locate and run to a real pass is **automatically demoted to `[CODE-TRACE]` and your `Verdict:` is flipped `CONFIRMED → CONTESTED [INTEGRITY-DOWNGRADE]`.** Claiming proof you don't have is worse than useless — it gets caught and your finding drops out of the verified set."

**F. Pre-PoC feasibility gates F1/F2 — `agents/skills/evm/verification-protocol/SKILL.md`:** "Gate F1: Reachability — Trace a call path from a permissionless entry point… If NO entry point reaches the vulnerable code → UNREACHABLE → FALSE_POSITIVE." "Gate F2: Math Bounds — Substitute real-world value domains… If the bug requires values outside feasible domains → INFEASIBLE → FALSE_POSITIVE." Before any verdict, the three pre-verification questions must have exact answers (the EXACT bug as "[Variable] is [read/written] at [location] but should be…"; the observable before/after difference; a real `assertEq(actualValue, expectedValue…)`), and the Evidence Audit table must tag every claim with its source class.

**G. Fork PoC mandate + `[UNPROVEN-EXTERNAL]` stamp — `rules/phase5-poc-execution.md`:** for "any Medium+ finding whose HARM is an **external-integration fund drain / misrouting**… the effective PoC class is floored to `integration`"; single-chain external dep at a known address → mandate pinned-block fork PoC asserting the harm (`forge test --match-test test_{ID} --fork-url {RPC_URL} --fork-block-number {PINNED}`); cross-chain relay leg → structured skip only; "No reachable fork RPC… the mandate is **inert**… stamp the finding `[UNPROVEN-EXTERNAL]`… The finding STAYS IN THE BODY at its **proven-mechanism severity**; R10 must NOT promote it ABOVE that severity."

**H. Verification completeness assert — `rules/phase5-poc-execution.md`:** Thorough: "`ASSERT: len(unverified) == 0`" across ALL hypotheses "including Low/Info"; Core: "verifies ALL Medium+, skips fuzz variants only". Mechanical and disk-checked by the orchestrator, not self-reported.

### 2.4 Adversarial judge mechanisms

**A. Skeptic-Judge inversion mandate — `prompts/shared/v2/phase5-skeptic.md` (Thorough only):** "Your job is to DISPROVE this finding. You are structurally opposed to its current verdict… You succeed when you identify a concrete defense, precondition, or environmental constraint that the verifier missed." Five axes: precondition feasibility, economic viability (gas/capital/opportunity cost), environmental constraints, severity calibration, alternative interpretations. "'All PoCs passed so skeptic is unnecessary' is NOT a valid skip reason. The skeptic tests different things than the PoC."

**B. Committed-invariant output:** when the skeptic names a blocking defense, it must "Commit that defense as a falsifiable assertion" as a `committed-invariant [CI-n]` block with a `Shape` from exactly six options — "`CONSERVATION`, `REQUESTED_EQ_DELIVERED`, `APPROVE_EQ_SPEND`, `NO_REVERT_AT_BOUNDARY`, `ROUNDTRIP`, `FRESHNESS`" — plus `Falsify Class: <property | boundary | roundtrip | conservation>`. "The block is mechanically harvested downstream into a falsifiable candidate — a survived assertion confirms the defense; a triggered one is a real bug the downgrade would otherwise have hidden." This converts *negative evidence* (why a bug is not a bug) into *re-testable positive claims*.

**C. Judge escalation rules and ruling table:** "1. `[POC-PASS]` outweighs theoretical arguments [effective_tag]; 2. `[CODE-TRACE]` with real constants outweighs speculation; 3. Concrete defense (code-level mitigation) outweighs 'the protocol could add a timelock'; 4. The side that cites more specific code locations (`file:line`) wins ties." Ruling table: DISAGREE + `SKEPTIC_WINS` → "Downgrade severity by 1 tier OR mark CONTESTED"; `UNRESOLVED` → "apply a one-tier severity demotion with floor Low", remain in the report body flagged `[UNRESOLVED - needs human review]` with both cases printed.

**D. Exploration skeptic — `phase4b6-exploration-skeptic.md` (Thorough only), the anti-over-filter guardrail:** a separate-context process auditing "whether the ANALYSIS BEHIND IT was COMPLETE along three axes" (direction completeness, …). Its **Recall-Positive Contract** is one-way: "You have the authority to: **ADD**… **UPGRADE**… **RE-OPEN**… You have NO authority to: **DROP** any existing finding. **MERGE**… **DOWNGRADE**… Any output that lowers severity, removes, or consolidates a prior finding is a contract violation. When in doubt, add or re-open — never suppress."


The skeptic-judge weighs the `effective_tag` from `verdict_manifest.json`, not verifier prose: "`[POC-PASS]` outweighs theoretical arguments — **but only when sourced from `verdict_manifest.json` `effective_tag`**, not from the verifier's prose `Evidence Tag` field… When `integrity_state == INFLATED_PROSE`… weigh the finding using the downgraded `effective_tag`, NOT the inflated prose claim."

**E. Assertion Retry Protocol (anti-gaming) — `rules/phase5-poc-execution.md`:** on assertion failure, self-diagnose with four questions ("Did I test the EXACT function at the EXACT location…? Is my assertion testing the CLAIMED HARM, not just a mechanism step? Did I use realistic values from the codebase (not made-up constants)?"); if all four are yes, accept `[POC-FAIL]` with ONE retry that "MUST keep the SAME target function call, the SAME harm assertion, and the SAME finding location"; "Attempt 2 tests a DIFFERENT function than the Location field → `[CODE-TRACE]`, not `[POC-PASS]`"; "Do NOT weaken the assertion to force a pass." Separately, "**Variant Exploration Before FALSE_POSITIVE**: Before marking FALSE_POSITIVE, test at least ONE relaxed variant of the attack… (timing…, amount…, ordering…, or initial state…). After 2+ variant failures → FALSE_POSITIVE is justified."

