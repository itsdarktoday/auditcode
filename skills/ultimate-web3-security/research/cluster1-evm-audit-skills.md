# Cluster 1: EVM Audit Skills — Deep Extraction Report

**Scope:** 9 repositories under `/home/nishan/ultimate-web3-security/sources/`:
`skills` (Auditmos), `0xsimao-ai`, `sc-auditor`, `Solidity-AI-security-auditor` (Kann), `cdsecurity-skills`, `drozer-lite`, `scv-scan`, `qs_skills`, `monethic-maia`.

**Method:** SKILL.md, README, methodology, prompt, reference, checklist, and template files were read in full or in representative depth. Quotes are verbatim. Per-repo sections cover: (1) contribution summary, (2) most valuable techniques, (3) contradictions, (4) gaps, (5) classification recommendation. A cross-repo synthesis and unified-skill blueprint close the report.

---

## Executive Summary

These 9 repos span the full spectrum of AI audit-skill design, from single-pass checklists to multi-phase adversarial pipelines. Three repos are orchestration-grade core methodologies: **0xsimao-ai** (accounting-first, 12 independent parallel lenses, hardest judge gates), **sc-auditor** (Map-Hunt-Attack state machine with Devil's Advocate scoring, skeptic inversion, proof-based conflict resolution, tool integration), and **monethic-maia** (multi-platform batched detector engine with FP-first adversarial verifier and a formal detector-authoring spec). **Auditmos** contributes the richest domain pattern library (liquidation math especially). **drozer-lite** is the best benchmark-calibrated pattern scanner with severity self-discipline. **qs_skills** contributes deep single-dimension taxonomies (reentrancy variants, replay types, invariant types) and the only blue-team release-gate skill. **Kann** contributes a storage-layer hunting agent and a real-finding cluster taxonomy. **scv-scan** contributes the cleanest two-tier reference-document standard (cheatsheet + full reference). **cdsecurity-skills** is the only pre-audit readiness skill (deliberately non-security).

The strongest single reusable idea across all repos is the **accounting-desync/asymmetry framing**: value moves, a tracked total must move with it, and the bug is the *missing or one-sided write* — stated most sharply by 0xsimao-ai ("*value leaves the contract but the variable tracking it is never decremented (or is decremented in only one of two branches)*") and independently reinforced by qs_skills' state-invariant detection, Kann's "lost write" category, and drozer-lite's cross-cluster "symmetric asymmetry" sweep.

---

## 1. `skills` (Auditmos) — 14 Domain Audit Skills

### 1.1 Contribution summary

A library of 14 ready-to-use Claude skills (`audit-lending`, `audit-liquidation`, `audit-liquidation-calculation`, `audit-liquidation-dos`, `audit-unfair-liquidation`, `audit-reentrancy`, `audit-signature`, `audit-state-validation`, `audit-math-precision`, `audit-oracle`, `audit-slippage`, `audit-staking`, `audit-clm`, `audit-auction`) plus a global `always-checklist.md`. Every skill ships the same five artifacts: `SKILL.md` (workflow), `checklist.md` (verification list), `reference.md` (pattern catalogue), `example.md` (vulnerable/fixed code), `templates/report-template.md` (finding + cost-analysis format). Notably, **five** skills cover liquidation from different angles (economics, calculations, DoS, unfairness, lending lifecycle) — the deepest liquidation coverage of any repo in this cluster.

### 1.2 Most valuable techniques

1. **Uniform per-skill workflow with a mandatory access-control-first triage gate.** Every skill repeats: "*3. **Validate exploitability** — **Check access control first** - grep for `onlyOwner|onlyAdmin|onlyGovernance` modifiers … Downgrade severity if admin-only unless direct user fund impact.*" This single rule is the cheapest FP-killer in the set and should be a global pre-gate.
2. **"MUST be exploitable by non-privileged actors" as a severity axiom.** Repeated verbatim in the Critical/High tier of every skill (e.g., audit-lending: "**Critical:** Fund loss, collateral theft, debt erasure without repayment, pool insolvency, **MUST be exploitable by non-privileged actors**"). This is the privilege-rule shared by all repos, stated as a severity constraint rather than a discard rule.
3. **Per-skill admin-only exception lists.** Each skill enumerates exactly when an admin-only issue escalates, e.g. audit-lending: "*Admin-only lending functions … are **MEDIUM or LOW severity** unless: Invalid parameters directly enable borrowers to avoid repayment … Pause mechanism asymmetry (admin pauses repayments but not liquidations) directly harms borrowers.*" Converts a coarse rule into a decision procedure.
4. **Per-skill false-positive whitelists ("False Positives - Do NOT Flag").** E.g. audit-liquidation: "*Protocols with trusted liquidators (not trustless)*"; audit-state-validation: "*OpenZeppelin Ownable2Step (already secure 2-step implementation)*". These encode domain judgment a generic auditor repeatedly gets wrong.
5. **MANDATORY checklist-verification deliverable gate:** "*Before deliverable, verify each `checklist.md` item against codebase. Flag violations as findings.*" Forces complete coverage rather than opportunistic findings.
6. **Liquidation domain decomposition (the strongest asset).** Four orthogonal liquidation skills:
   - *liquidation* (incentives): "No liquidation incentive → trustless liquidation unprofitable"; "Partial liquidation bypasses bad debt → liquidators extract value, protocol absorbs loss"; "No partial liquidation → whale positions exceed liquidator capacity".
   - *liquidation-calculation* (math): "Unprioritized liquidator reward → other fees paid first, no incentive remains"; "Excessive protocol fee → 30%+ fees make liquidation unprofitable"; "Oracle sandwich self-liquidation → users profit from triggering oracle updates"; "**Profitability** - total fees < liquidation bonus to maintain incentive."
   - *liquidation-dos* (availability): 13 patterns including "Fixed bonus exceeds collateral → 110% bonus fails when ratio < 110%", "Multiple nonReentrant → conflicting guards block execution", "Token deny lists → USDC blocklists prevent transfers", "Single borrower edge case → assumes > 1 borrower".
   - *unfair-liquidation* (fairness): "Missing L2 sequencer grace period → users liquidated immediately when sequencer restarts"; "Interest accumulates while paused"; "No LTV gap → users liquidatable immediately after borrowing"; "Unhealthier post-liquidation → liquidator cherry-picks stable collateral".
7. **Key Principles blocks** — 5-7 design axioms per domain that double as remediation guidance (audit-liquidation-dos: "*Bounded iteration - never loop over unbounded user-controlled arrays; Graceful degradation - liquidation should work even with bad debt/edge cases; Callback isolation - external calls cannot revert liquidation*").
8. **Report template with quantified cost analysis.** The liquidation-dos template includes a **Gas Analysis** table ("*Positions: 10,000 small positions … Total gas: 10,000 × 3k = 30M gas … Result: Out of gas revert*"), a **DoS Attack Cost Analysis** (attack cost vs defense cost), and a **Token Compatibility Matrix** (`USDC 6 decimals / USDT reverts on zero / NFT callbacks`). Most operational PoC-adjacent format in the cluster.
9. **always-checklist.md** — the minimal universal gate list: CEI pattern, cross-function reentrancy, **read-only reentrancy**, fee-on-transfer, rebasing, callbacks (ERC777), zero-transfer-reverting tokens, pausable tokens, decimal scaling, two-step ownership, role segregation, emergency pause, timelocks.
10. **Consistent output discipline**: "*DON'T: … Use vague terms (\"could be vulnerable\"); Ignore context (grace periods elsewhere, admin controls)*"; DO blocks demand line references, executable PoCs, quantified impact, timing calculations.
11. **Signature skill checklist** (compact but complete): nonces verified+incremented, chain_id in EIP-712 domain, all relevant params signed, deadline + `block.timestamp <= deadline` check, ecrecover != address(0), OZ ECDSA for malleability, verification before state changes (CEI).
12. **Math-precision severity by quantified thresholds**: "*Critical: Direct fund extraction, >10% value loss, no preconditions required; High: 1-10% value leakage*" — one of the few places a repo pins severity to a numeric loss band.

### 1.3 Contradictions with other methodologies

- **Severity rubric inconsistency across its own skills**: math-precision uses percentage bands (>10% = Critical) while lending/liquidation use "MUST be exploitable by non-privileged actors" as the Critical criterion; a 0.5% looping drain would be Critical under 0xsimao's loop rule but Medium under Auditmos' band.
- **Admin-only treatment is downgrade-not-discard**, vs 0xsimao's "*Do not report: Admin-only functions doing admin things*" and drozer-lite's "Cap at MEDIUM … centralization risk". Auditmos keeps admin findings as Medium/Low with carve-outs; 0xsimao refuses them unless a concrete mechanism names an unbounded parameter.
- **"No liquidation slippage protection" is Medium** in unfair-liquidation, while 0xsimao's liquidation lens quotes "*Lack of slippage protection leads to loss of protocol funds*" as a High vein and audit-slippage rates zero minAmountOut Critical. Severity calibration for the same bug class differs by ~2 tiers.
- Read-only reentrancy is High in audit-reentrancy severity but "view function reentrancy without exploitable impact" is Low — consistent with qs_skills but stricter than drozer-lite's DROP-without-in-scope-callback-token rule.
- audit-slippage claims "No slippage parameter (minAmountOut = 0) → 99%+ value extractable" — drozer-lite and 0xsimao both require distinguishing user-chosen swaps (accepted MEV) from protocol-owned swaps; Auditmos only covers the internal-swap exception in its false-positive list.

### 1.4 What it lacks

- No orchestrator or multi-pass architecture: each skill is single-shot; no money-model building, no dedup/judge/verifier stage, no interplay between skills (a liquidation bug may be double-reported across 3 liquidation skills).
- No accounting-model or invariant-extraction step (the core of 0xsimao/qs_skills).
- No tool integration (no Slither/Aderyn/fuzzers/PoC), no static-analysis pre-pass, no benchmark/regression cases.
- No per-finding evidence schema or confidence field; report template is prose-based; no checkpointing for interrupted audits.
- Skill `description` triggers are narrow keyword lists; automatic triggering may miss variants.

### 1.5 Classification recommendation

**Specialized sub-skill library + reference material.** Use the 14 skills as *domain lens seeds* inside a unified auditor (attach the liquidation-calculation and liquidation-dos pattern lists to the accounting/liquidation lens), and reuse `always-checklist.md`, the `checklist.md` files, and the report templates as reference material. Not a core methodology on its own — no orchestration, verification, or dedup layer.

---

## 2. `0xsimao-ai` — Accounting-First 12-Lens Audit (style of 0xSimao)

### 2.1 Contribution summary

The strongest core methodology in the cluster. Reverse-engineered from 0xSimao's 869 published findings (177 High, 247 Medium) across 143 reviews. The orchestrator builds a protocol **money map**, bundles it with the full source, spawns **12 independent parallel lens subagents**, then runs a single-pass dedup + 4-gate judge and formats the report. Ships the method (`simao-method.md`), 12 attack-lens files, shared lens rules, severity-calibration gates, and report formatting. Explicitly model/harness-agnostic with a documented sequential fallback.

### 2.2 Most valuable techniques

1. **The core thesis (verbatim):** "*build the protocol's accounting model first, then find the one step in a multi-step sequence where a tracked total desyncs from reality — and prove who is left holding the loss.*"
2. **The drift taxonomy** (simao-method.md) — the single best bug-classification table in the cluster:
   - The write is missing → "value moved and no variable recorded it — or one branch updates it and the sibling branch does not"
   - The write is wrong → "wrong amount, direction, rounding, units, or decimals"
   - The write is mistimed → "someone's snapshot is taken against state that is about to change"
   - The write goes to the wrong party → "the total is intact; the split between cohorts is not"
   - The input was never trustworthy → "faithfully propagated from an oracle, a live balance, or a caller-supplied parameter an attacker controls"
   - The state is unreachable → "a revert, a pause, an unbounded loop, or a missing path means it can never be settled"
3. **"Who is left holding the loss?" victim-naming gate**: "*Answer with a named class of actor, never \"users\". For accounting drift it is often whoever withdraws last … If the only person worse off is the caller, there is no finding.*"
4. **Phase 0 — learn the protocol's vocabulary**: "*His findings are written in the protocol's language: `cdsPoolValue`, `abond`, `downsideProtected` … Before hunting, be able to state in plain English: What does a user give, and what claim do they receive in return? … What happens when the protocol is short — who absorbs the shortfall?*"
5. **The money map** (Turn 2): assets, **tracked totals** ("*every storage variable that claims to represent an aggregate … For each: **every** function that writes it, and whether that write is a `+` or `-`*"), the **asymmetry table** ("*This table alone produces his most common High*"), **invariants** ("*5–15 statements … in the form `sum(user claims) <= actual balance`, `totalX == Σ userX`, `index only increases`, `every credited unit is debited exactly once`*"), lifecycles, and cohorts. Capped under ~200 lines; short honest version for accounting-light targets (routers, verifiers).
6. **12 independent lenses**: accounting-desync, share-exchange-rate, temporal-cohort, liquidation-solvency, cross-chain-state, rounding-precision, ordering-mev, dos-griefing, access-trust, integration-assumptions, edge-states, flow-completeness. Independence is load-bearing: "*each sees only its own bundle and never another lens's output. That independence is what makes agreement between two lenses evidence rather than an echo.*"
7. **Mandatory reasoning-protocol markers** (shared-rules.md): `[Model: <name>]` (plain-English money model per function), `[Why: <file:line>]` (drill past "that is how it is written"), `[Defeat: <function>]` (three concrete attacker moves, "*Specific addresses, values, and states — never abstractions*"), `[LastOut: <lifecycle>]` (walk every user withdrawing in worst order). "*The orchestrator checks marker counts.*" This is the most direct anti-shallow-scan mechanism anywhere in the cluster.
8. **Saturation mandate**: "*When you find a bug, weaponize the pattern across the entire codebase before moving on. Search by function name AND by code shape … A repeat instance you missed is an audit failure.*"
9. **FINDING vs LEAD distinction**: "*FINDINGs have a concrete, unguarded, exploitable path with a named victim. LEADs have a real accounting or logic smell with a partial path. Default to LEAD over dropping — never drop.*" Leads are emitted, never silently discarded.
10. **Structured finding schema** with `group_key: Contract | function | bug-class` for dedup, plus `internal_pre`/`external_pre` preconditions — "*An `internal_pre` or `external_pre` of `None` is the strongest possible finding — never pad these to look thorough.*"
11. **Dedup hard gates** (Turn 6): "**MANDATORY — Function isolation (HARD).** NEVER merge across different `function:` fields. Different function = different bug." + **mechanism preservation** ("*The same function routinely carries several coexisting accounting bugs — Autonomint's `withdraw` path alone produced six separate Highs*") + **mitigation preservation** (distinct fixes become Option A/B) + **completeness gate** ("*every unique (Contract, function) appearing in ANY raw FINDING or LEAD … MUST have ≥1 item in the final report*").
12. **Four severity gates, committed in one pass** (severity-calibration.md): Gate 1 — "*Does a code path actually stop this? … One `BLOCKS` on the critical path kills the finding — reject it, do not demote it*" with named false-positive killers (nonReentrant assumed absent, upstream bounds, ≥0.8 overflow reverts, virtual-share offsets, storage vs manipulable source); Gate 2 — precondition cost (flash-loanable = ALLOWS); Gate 3 — "*Is the harm to someone other than the attacker?*" with named victim classes; Gate 4 — "*Is the impact real value, or theatre?*". "**`UNCERTAIN` counts as `ALLOWS`** — an unproven guard is not a guard."
13. **Calibration checks**: "*Do not inflate a DoS to High unless funds are stuck permanently, or the block prevents liquidations. … Do not deflate an accounting desync to Low because the per-transaction amount is small. If it is repeatable or compounds, it is a drain. … A rounding error is only Low if it cannot be looped. Check that first, always.*"
14. **The edge-states lens checklist** — run against every stateful function: zero/empty, one/sole-occupant, first, last ("*his highest-yield edge: run the full unwind and check whether the final actor is paid and whether residual value is trapped*"), expired/matured/ended, paused/frozen, cancelled/retried, maximum/saturation, threshold boundaries ("*test exactly at, one below, and one above*"), reconfiguration mid-flight.
15. **The flow-completeness lens's four symmetries**: inverse symmetry ("*Whatever the forward path writes, the inverse must unwrite. List the forward's state writes in one column and the inverse's in the other; every unmatched row is a candidate*"), sibling symmetry, branch symmetry, precondition symmetry ("*Every function that consumes derived state must first refresh it … Then check the refresh itself updates its own `lastUpdated`*"). Plus "wrong-thing-validated", "return value discarded", "documented-but-absent" ("*Read the docs … as a specification, then verify each claim in code. A behavior the docs promise and the code does not implement is a finding*"), copy-paste divergence.
16. **Liquidation-solvency lens**: "*Check the health formula against the liquidation formula. The predicate that says \"liquidatable\" and the math that executes the liquidation are often written by different people*"; "*Accrue before you judge*"; "*Follow every variable liquidation touches … Missing counterparts here are his signature High*"; "*Verify bad debt actually clears*"; "*Cap the price and the seize.*"
17. **Temporal-cohort lens test**: "*write the two-user timeline explicitly: Alice deposits at t0, value V accrues by t1, Bob deposits at t1, distribution happens at t2 … If Bob receives anything from the t0→t1 accrual, that is the finding — quantify Alice's loss.*"
18. **Report discipline**: titles carry mechanism + consequence ("*Never write a vague title*"), Description + Recommended Mitigation only, minimal fix in the protocol's own terms ("*`Decrease raBalance in the early-redemption branch as well.` … Not \"refactor the accounting system.\"*"), honest likelihood statements, and a closing **Unverified leads** section — "*Leads are calibration, and a client reads them as the map of where to look next.*"
19. **Do-not-report list** codifying accepted tradeoffs: admin doing admin things, ordinary MEV on user-chosen swaps, rounding dust without amplification, first-depositor inflation where MINIMUM_LIQUIDITY exists, self-harm-only, centralization-risk-without-mechanism, gas optimizations, missing zero-address checks on admin setters.

### 2.3 Contradictions with other methodologies

- **No Critical severity** (only High/Medium/Low/Info) — every other repo except cdsecurity uses a Critical tier. In practice 0xsimao's High bucket absorbs what Auditmos/drozer call Critical (e.g., "anyone can seize a privileged position" is listed under High).
- **Privileged roles**: stricter than Auditmos (no downgrade-and-keep for admin findings; they are excluded unless a concrete mechanism is named) but looser than sc-auditor's blanket "Privileged roles act in good faith" + 4 exceptions — 0xsimao's access-trust lens DOES report privileged-role abuse when "the bounds are not enforced on-chain and the composition is a rug … when you can name the concrete mechanism and the parameter that is unbounded".
- **Single-pass judging**: Turn 6 forbids revisiting a gate verdict ("*Commit; do not revisit*"), whereas sc-auditor runs a full second-pass skeptic with inversion mandate plus a judge; monethic runs an isolated adversarial verifier. 0xsimao consciously trades verification depth for determinism and speed.
- **No tool verification**: numeric attack paths replace PoCs; sc-auditor's benchmark mode would hide 0xsimao-style findings without `proof_type`.
- **Transient state**: bundle dir is auto-removed (`rm -rf {bundle_dir}`); no checkpointing/resume, unlike sc-auditor's manifest discipline.
- Agreement: its "do not report" list closely matches drozer-lite's weak-evidence floor and scv-scan's false-positive-first ethos, and its `UNCERTAIN = ALLOWS` matches sc-auditor's "partial mitigations never dismiss alone".

### 2.4 What it lacks

- No static-analysis tooling, fuzzing, or PoC execution; proofs are narrative/numeric.
- No user gates (fully autonomous — sc-auditor and Auditmos both assume a human reviews scope/invariants; 0xsimao prints a 5-line money-map summary but does not wait).
- No interactive model selection when the runtime lacks it; sequential fallback is explicitly weaker ("*the passes are no longer blind to each other*").
- Bundle-based context (all source concatenated) breaks on very large repos; no chunking/windowing strategy like monethic's.
- Liquidation/oracle/signature coverage is deep on accounting angles but thinner on Auditmos' exotic liquidation-DoS edge cases (deny lists, conflicting nonReentrant) — complementary, not overlapping.

### 2.5 Classification recommendation

**Core methodology + judge mechanism.** The money-map + 12-lens + drift-taxonomy + 4-gate judge is the best candidate for the spine of a unified EVM audit skill. Its lens files are also first-class reference material. Reuse its severity-calibration and report-formatting files as the shared judge/report standard.

---

## 3. `sc-auditor` — Map-Hunt-Attack Interactive Pipeline with DA Protocol

### 3.1 Contribution summary

An interactive, checkpointed, subagent-orchestrated audit pipeline: RESUME CHECK → RESOLVE INPUT → SETUP (Slither/Aderyn) → MAP (SystemMapArtifact + user gate) → HUNT (5-6 parallel lanes + user gate) → ATTACK (per-hotspot agents, DA-first, mandatory proof attempt) → VERIFY (skeptic inversion + judge) → CONFLICT RESOLUTION → REPORT. Ships 405-line SKILL.md, 12 prompt files, attack-vector docs, and hard-negatives docs. The most rigorous *verification* layer in the cluster.

### 3.2 Most valuable techniques

1. **Non-negotiable state machine**: "*1. STATE MACHINE IS ABSOLUTE: Follow phases in exact order … NEVER skip, reorder, or combine phases. 2. USER GATES ARE BLOCKING … Do NOT auto-advance.*"
2. **Orchestrator does not audit**: "*ORCHESTRATOR DOES NOT AUDIT: If you find yourself reading .sol files to analyze security, STOP. That is a sub-agent's job.*" Plus minimal-context dispatch: "*forward ONLY the inputs listed for that phase. Do NOT forward conversation history, audit intent, or prior phase reasoning*" — prevents cross-phase bias.
3. **Checkpoint discipline** (4 rules): agents self-checkpoint as final step, "*ALWAYS reload it from the checkpoint file — never rely on in-context data alone*", checkpoint before user gates, integrity check on resume — with a manifest JSON schema. This is the only repo with resumable-audit engineering.
4. **SystemMapArtifact** schema: components, external_surfaces, auth_surfaces, state_variables, **state_write_sites** (with write_type assign/increment/decrement/delete/push/pop), external_call_sites (with `before_state_update` flag), **value_flow_edges**, config_semantics, protocol_invariants, audit_units. This is the machine-readable equivalent of 0xsimao's money map — the two should be merged (money map = semantics; SystemMap = graph).
5. **Five HUNT lanes + auto-triggered adversarial-deep 6th**: callback_liveness, accounting_entitlement, semantic_consistency, token_oracle_statefulness, economic_differential; adversarial_deep activates "*if the SystemMap shows cross-contract interaction patterns … not only in deep mode*". Lanes are assigned unscored AuditUnits by characteristics.
6. **Accounting-entitlement lane patterns**: stale balance reads, transfer/burn entitlement drift ("*Cross-reference `systemMap.value_flow_edges` to verify that every debit has a matching credit of equivalent value*"), reward attribution, historical fee capture, share/reward state mismatch.
7. **Adversarial-deep Phase C — Semantic Tension Analysis**: argue "preserves invariant" and "enables exploit" for the same path; "*When BOTH arguments survive scrutiny … Escalate to `critical` or `high` — these are the findings most likely to be real and most likely to be missed*." Also hotspot combination matrix (causal chain, shared state, temporal ordering) and 3+ transaction sequences with amplification factor.
8. **Economic-differential lane patterns**: exchange-rate symmetry ("*deposit(X) → withdraw() < X - declared_fees*"), rate change between check and use, boundary behavior (zero/max/dust/first-deposit), fee compounding across hops, incentive alignment ("*Is there a profitable deviation from honest behavior that doesn't require privilege?*").
9. **The 6-dimension Devil's Advocate protocol** (da-protocol.md): guards, reentrancy_protection, access_control, by_design (safe/risky-tradeoff/undocumented), economic_feasibility, dry_run ("*Execute the exploit sketch with concrete values. Check arithmetic behavior, rounding, overflow*"). Scoring -3/-2/-1/0/+1 with evidence required per dimension; decision rules: one -3 AND total ≤ -6 → invalidated; -5..-3 → degraded; -2..+2 → sustained; ≥ +3 → escalated. "*Partial mitigations DEGRADE confidence. They NEVER dismiss alone.*"
10. **Quick Veto before full DA**: "*What single check makes this attack impossible?*"; one incontrovertible check scores -3 and can kill the finding early — saves the most expensive analysis.
11. **Privilege Rule with 4 exceptions**: "*Privileged roles (owner, admin, governance) ACT in good faith*" BUT do not discard: authority propagation, composition failures, flash-loan governance, config interaction. The most precise statement of the cluster-wide privilege question.
12. **ATTACK exploit sketch schema**: attacker, capabilities, preconditions, tx_sequence, state_deltas, broken_invariant (INV-xxx), `numeric_example` ("*deposit 1 wei, donate 1e18, victim deposits 1e18, gets 0 shares*"), `same_fix_test`. "*If the exploit sketch CANNOT be completed … DO NOT dismiss — carry the finding forward as a candidate.*"
13. **Mandatory proof attempt**: "*Each ATTACK agent MUST attempt at least one proof method for confirmed vulnerabilities … Findings without proof stay `status = \"candidate\"`, `proof_type = \"none\"`.*" Tools: generate-foundry-poc, run-echidna, run-medusa, run-halmos. Only repo with proof-based status.
14. **VERIFY skeptic with inversion mandate**: resurrect (if ATTACK invalidated), negate (if sustained), or push-toward-invalidation (if degraded); fresh independent DA; "*Proof Burden on Negation … Without concrete proof, your negation claim FAILS and ATTACK verdict holds.*"
15. **Judge "prove it or lose it"** conflict resolution + Standard Matrix mapping (DA agreement × proof availability/pass) to final statuses: verified / judge_confirmed / candidate / discarded — with benchmark_mode_visible gating on proof_type. Report has 5 sections: Proved, Confirmed (Unproven), Detected Candidates, **Design Tradeoffs** ("*Document the tradeoff, do not dismiss*"), Discarded with DA chain reasoning.
16. **Hard negatives docs**: per-vector false-positive refutations with "Why It Looks Bad / Why It's Safe / Key Indicators" — e.g., lazy MasterChef reward update is safe because "*the catch-up calculation and the state update happen in the same transaction, before any external calls*"; internal-accounting-is-safe because "*the protocol is immune to external manipulation of its token balance*". Prevents the most common AI FP classes.
17. **Dedup key**: cluster by "*(contract, function, state_vars, invariant, fix_shape)*" — "*Two findings with the same root cause but different fix shapes are distinct*", echoing 0xsimao's mechanism-preservation rule.
18. **Solodit usage policy**: static-analyzers may NOT search findings in MAP; HUNT may "*ONLY after establishing a local anchor (contract + function + bug family identified first from code analysis). Never use Solodit to discover hotspots from scratch*" — a reusable anti-anchoring rule for any KB lookup.

### 3.3 Contradictions with other methodologies

- **Blocking user gates** vs every other repo's autonomy (0xsimao, Kann, maia, drozer, scv are one-shot). Trade-off: accuracy/scope control vs unattended runs. A unified skill needs a `--autonomous` flag to reconcile.
- **Proof requirement**: "verified" needs a passing artifact; 0xsimao accepts numeric attack paths, monethic only a verifier verdict, drozer a code-trace sentence. sc-auditor's bar is the highest and will demote real findings in environments without Foundry/fuzzers.
- **GAS as a finding severity** (CRITICAL|HIGH|MEDIUM|LOW|GAS|INFORMATIONAL) vs 0xsimao's "Gas optimizations dressed as vulnerabilities" are not findings, and cdsecurity's "Never flag: gas optimizations". sc-auditor reports GAS as informational severity but benchmark-hides unproven HIGH/MEDIUM — a pragmatic middle.
- **Privilege rule is formalized** (good-faith + 4 exceptions) where 0xsimao relies on case law in lens text; both reach nearly the same answer, but sc-auditor's config-interaction exception would elevate some findings Auditmos demotes to Medium.
- **Orchestrator never reads source**: 0xsimao's orchestrator reads find results and builds the money map itself; sc-auditor forbids it. Philosophy: sc-auditor protects against orchestrator bias; 0xsimao needs the orchestrator to synthesize the model. A unified skill must pick: (a) orchestrator builds the model (0xsimao) then (b) downstream lanes are fed minimal context (sc-auditor) — these compose, but the "orchestrator does not audit" rule must be softened to "orchestrator models, does not hunt".

### 3.4 What it lacks

- Liquidation/oracle economics depth (Auditmos has 5 liquidation skills; sc-auditor has one lane bullet).
- Accounting is a lane, not the spine — the economic_differential and accounting_entitlement lanes are thinner than 0xsimao's dedicated lenses.
- Requires MCP server (`mcp__sc-auditor__*`) for the tool layer; skill degrades without it.
- No output-budget/progress protocol (monethic) — long pipelines risk context exhaustion; mitigated only by checkpoints.
- User-gated phases make unattended CI use impossible without modification.

### 3.5 Classification recommendation

**Core methodology (pipeline/state machine) + judge mechanism + tool integration.** Adopt its phase discipline, checkpointing, DA protocol, skeptic/judge conflict resolution, and MCP tool hooks as the *verification spine* of a unified skill; use 0xsimao's lenses as the *hunt content* and Auditmos/qs_skills taxonomies as lens seeds.

---

## 4. `Solidity-AI-security-auditor` (Kann AI Labs)

### 4.1 Contribution summary

A two-lane parallel pipeline: **Cluster Checker** (scans against a corpus of `cluster_pages/` — real vulnerability clusters with ranked labels and original finding text) and **State Hunter** (a dedicated storage-layer agent: lost writes, attacker-influenced slot writes, upgrade collisions, dangerous storage semantics), then a **judging agent** (FP gate + dedup) and **report-formatting agent**. The storage-layer specialization and the cluster-taxonomy-driven scanning are unique in the cluster.

### 4.2 Most valuable techniques

1. **State Hunter's two entry gates** — Gate 1: state-mutating logic exists; Gate 2: at least one storage-risk signal (struct/array/mapping writes, `sstore`/`sload` assembly, manual slot constants, proxy/delegatecall). "*If either fails, output `\"Scope requirements not met.\"` and stop.*" This is a clean model for *gating any specialized lens on surface presence* (mirrors 0xsimao's "short honest map" for accounting-light targets).
2. **Storage inventory before hunting**: map every persistent state variable and all mutating functions, "*This anchors every finding to a real write path.*"
3. **Skip/Borderline/Survive triage with exclusivity**: "*Every category must appear in exactly one tier*" — Skip (structurally impossible), Borderline ("*promote only if you can name the exact function AND the exact line number AND describe the exploit in one sentence*"), Survive (clearly present).
4. **Structured deep-analysis line format**: "*`CAT-2: path: updatePosition() → _sync() → pos copied to memory | guard: none | verdict: CONFIRM [88]`*" — forces path + guard + verdict per category, preventing free-form vagueness.
5. **CAT taxonomy with ALL-criteria confirmation**: e.g., CAT-1 lost write confirms only if ALL of (storage value assigned to non-storage variable, mutated, never written back on all reachable paths, context signals intent); each category has explicit DROP conditions ("*function is `view`/`pure`, copy is intentional, variable is a storage pointer*").
6. **Cluster batching with a 40% promotion gate**: read only `## Label` of 25 clusters at a time, estimate match %, "*Below **40%** → `SKIPPED`. At **40% or above** → `PROMOTED` … Discard skipped cluster data immediately — do not retain it in context*". A concrete context-window management technique for large KBs.
7. **Per-cluster subagents with 2-3 concurrency**, each receiving full cluster definition + codebase + judging rules; each must trace the full call path and apply the FP gate; output fixed-format blocks (`CLUSTER / TITLE / SEVERITY / LOCATION / DESCRIPTION / ATTACK PATH / RECOMMENDATION`).
8. **Cluster corpus provenance**: cluster files carry `Rank`, `Count`, an auto-generated `Label`, and original finding text (e.g., proxy initialization calldata validation). Taxonomy-as-data, not hand-written heuristics.
9. **Judging agent's 3-check FP gate**: "*1. A concrete/partial attack path exists: caller → function call → state change → loss or impact. 2. The entry point is reachable by the attacker. 3. No existing guard already prevents the attack.*" Plus a do-not-report list (owner/admin by design, missing events, centralization-without-exploit-path, implausible preconditions).
10. **Below-threshold separator** instead of silent drops: partial attack paths, self-contained impacts, privileged-caller findings go "below the threshold separator … included in the output but marked separately" — the same philosophy as 0xsimao's Unverified leads and monethic's needs-manual-review.
11. **Report template with diff-required fixes**: "*Include a diff block for findings with severity Critical or High … For Medium and below, describe the fix in prose without a diff*"; attack scenario as numbered concrete steps; AI-disclaimer that the report "*has not been manually verified by a human auditor*" and "*The absence of a finding does not guarantee the absence of a vulnerability*" — the honest caveat other repos omit.
12. **Strict role separation in the pipeline**: judging agent "*You do not analyze code. You do not add new findings*"; formatting agent "*You do not add, remove, or modify findings*". Clean separation of detection/judgment/formatting stages.

### 4.3 Contradictions with other methodologies

- **Judge does not re-verify code** — it validates *reports* against gates, trusting scanner subagents' traces. sc-auditor and monethic run independent verifiers precisely because they distrust the first pass; 0xsimao's orchestrator does not re-read source either ("*Do NOT re-read source to re-verify the top finding — the lenses did that*"), so Kann aligns with 0xsimao but contradicts sc-auditor/maia.
- **Storage-only scope**: the state hunter deliberately ignores logic/economic/oracle bugs that Auditmos and 0xsimao prioritize; a unified skill would treat it as one lane among many.
- Severity scale has Critical→Info with no numeric calibration (contrast 0xsimao gates, drozer table, sc-auditor DA scoring).

### 4.4 What it lacks

- No accounting/invariant model, no lifecycle analysis, no oracle/liquidation economics, no MEV lens.
- No tool integration (no Slither/fuzzers/PoC); cluster taxonomy is opaque (numeric IDs without a thematic index file in the skill itself).
- No checkpointing, no user gates, no dedup beyond root-cause + highest severity; no confidence field.
- No money-map/report-header protocol model (the report jumps straight to findings).

### 4.5 Classification recommendation

**Specialized sub-skill (storage-state hunting) + reference material (cluster taxonomy) + lightweight judge mechanism.** Adopt the State Hunter as a dedicated lane in a unified auditor, the 40%-promotion batching as the standard way to load large detector KBs, and the 3-check FP gate as the minimum pre-judge filter.

---

## 5. `cdsecurity-skills` — Audit Readiness (audit-prep + rust-audit-prep)

### 5.1 Contribution summary

A **pre-audit** orchestrator, deliberately not a vulnerability hunter: 8 scored phases (test coverage, test quality, NatSpec docs, code hygiene, dependency health, best practices, deployment readiness, project documentation) + optional static analysis, `--fix` auto-fixes, template generation (SECURITY.md, scope.md, KNOWN_ISSUES.md), CI mode with score threshold. A Rust variant mirrors the structure.

### 5.2 Most valuable techniques

1. **Explicit non-goal**: "*Do NOT perform security vulnerability analysis or threat modeling … Do NOT suggest architecture changes or redesigns.*" Positioning this as stage 0 of the audit lifecycle is the right division of labor.
2. **Scored, capped rubric**: "*Score = 100 minus deductions (min 0, max 100). Apply deduction caps from your checklist.*" Per-check deductions with caps (e.g., undocumented public function -3 cap -60; compiler warnings -10 cap -30).
3. **Coverage gate**: "*if branch coverage < 90%, emit this FAIL: … `Branch coverage XX% — audit requires minimum 90%` … signals the project is NOT audit-ready*" — an opinionated, falsifiable readiness bar.
4. **Structured FAIL/PASS lines**: `FAIL | <check> | <-N> | <file:line>` + `desc:` (factual problem) + `fix:` (specific actionable instruction) + `PASS | <check>` + `note:` (evidence). Machine-parseable and fix-oriented.
5. **NatSpec counting by grep patterns** (function/contract/event/public-state-variable patterns; `@inheritdoc` counts as fully documented) with **standard-override skip lists** (ERC20/721/1155/4626 getters are "*self-explanatory from the standard*") and **stale @param detection** ("*Grep for `@param` with -A3 context … Flag any @param that references a parameter not in the signature (copy-paste error)*").
6. **SECURITY.md template with trust-assumption sections**: "*Roles & Permissions, Trust Assumptions, Centralization Risks, Known Risks … Pre-fill role names from AccessControl/Ownable usage in source*" — converts centralization concerns into documented, auditable assumptions (feeds 0xsimao's "documented invariant that the code violates is his highest-yield finding source").
7. **KNOWN_ISSUES.md skeleton**: "*Document any known limitations, accepted risks, or intentional design trade-offs here.*" — the counterpart to sc-auditor's design_tradeoff report section.
8. **Scanner-priority policy**: "*Priority when multiple sources available: MCP > local CLI > skill*" and scanner findings "*do NOT affect the audit-prep score*" — clean separation between readiness score and security findings.
9. **`--diff <ref>`** scoping to changed files; `--ci` JSON + exit-code threshold; timeouts on tool runs (300s).

### 5.3 Contradictions with other methodologies

- **It is the only repo that forbids security analysis** — no direct conflict, but it shows the boundary a unified skill must draw: readiness checks never bleed into findings.
- "Never flag gas optimizations" and "functions >50 lines, magic numbers, naming conventions, code style" align with 0xsimao's do-not-report and drozer's INFO tier, but contradict sc-auditor's GAS severity slot.
- Its 90% branch-coverage bar conflicts with no one directly, but 0xsimao/maia/drozer audit without any coverage prerequisite — a unified skill should offer the gate as an option, not a requirement.

### 5.4 What it lacks

- Everything security-related by design (no taxonomy, no exploit reasoning, no severity model for bugs).
- EVM: Solidity-only in the main skill (Rust variant exists but is a fork, not a unified multi-language path).
- Scoring weights are asserted, not calibrated against any benchmark.

### 5.5 Classification recommendation

**Specialized sub-skill (pre-audit readiness / validation-adjacent)**. Wire it as the optional "Phase 0 — Readiness" of a unified skill, and reuse its SECURITY.md/KNOWN_ISSUES.md generation as input to the money-map/docs-as-specification step.

---

## 6. `drozer-lite` — Provenance-Cited Pattern Scanner with Cross-Cluster Sweep

### 6.1 Contribution summary

A multi-language (Solidity, Rust/Anchor/CosmWasm/IC, Move, Cairo, Vyper) **pattern-level** scanner: 8-step workflow (target/language detection → structural inventory → profile auto-detection → cluster analysis → per-check analysis with severity table → cross-cluster sweep → three gates → dedup/consolidation → JSON output). ~110 universal checks + domain profiles (lending, dex, math, reentrancy, oracle, signature, vault, stableswap, cross-chain, governance, gaming, solana, icp) — every check cites its provenance from real benchmark misses. Explicitly positions itself below `/droz3r` (full pipeline).

### 6.2 Most valuable techniques

1. **Provenance-per-check**: "*Every check in the bundled checklists traces to a real audit finding that was missed in past benchmark runs. The provenance is cited inside each check*" — e.g. `UNI-98 auto-route balance` traces to universal-invariants.md. This makes the KB self-auditing and is the standard other repos' checklists lack.
2. **Honest capability statement**: "*Does NOT do multi-step actor reasoning, chain composition analysis, or formal verification … drozer-lite finds the bugs pattern matching CAN find, fast and reproducibly, without pretending to be a full audit pipeline.*"
3. **Language-translation table** for function/modifier/state-variable/reentrancy-guard concepts per language, with the rule: "*translate the Solidity-phrased red flags to the target language's equivalent. The METHODOLOGY is language-agnostic; only the SYNTAX differs.*"
4. **Structural inventory before analysis** ("*context_map for cross-file detection*"), profile auto-detection (3 keyword matches, `\w*` regex tolerance), universal profile always loaded.
5. **Severity decision table** keyed on caller privileges + impact — the most operational severity rubric in the cluster, e.g.: "*Direct drain / unauthorized mint … permissionless … protocol-wide funds at risk, no preconditions → **CRITICAL***"; "*Missing access control on a function that sets an economic parameter … **HIGH***"; "*Missing access control on a function that sets **per-user** state … **MEDIUM***"; "*Missing nonReentrant guard with no callback-enabled token in scope — speculative — **DROP — FP risk***"; "*Admin action with no timelock … **MEDIUM** (centralization)*"; "*Griefing / DoS affecting ALL users of a critical function … **HIGH***".
6. **Weak-evidence severity floor**: cap at LOW when the loss depends on "*off-chain tree / payload construction … cross-contract configuration the admin sets later … unobservable user ordering … external callback behavior on callee types that are not in the current whitelist*" — kills the "sounds concrete but depends on unobservable context" FP class.
7. **Cross-cluster sweep — 13 patterns**: symmetric asymmetries (state write/read mismatch, cross-contract ACL gaps in wrappers, auto-route fallbacks with "*If found, severity MUST be at least HIGH*", service-interface failure modes, shared-modifier inconsistency, pause-state asymmetry) + economic cross-cluster flows. "*This is the step that catches bugs single-cluster analysis misses.*"
8. **Three gates, and Gate C is anti-self-invalidation**: after an exploit sentence gate and a second gate, Gate C "*prevents the agent from reasoning itself out of reporting real bugs that the pattern matcher correctly identified*" — the explicit counterweight to the FP-first verifiers in monethic/sc-auditor. Both directions of the confidence-error problem get a gate here.
9. **Severity-tier output filter**: default output = CRITICAL/HIGH/MEDIUM only; LOW/INFO move to `warnings[]` ("*most scoring rubrics penalize them as false positives*"), with a **schema-mismatch rule**: "*if LOW/INFO cannot be emitted to `warnings[]`, they cannot be emitted at all*" — benchmark-aware self-censoring absent everywhere else.
10. **Root-cause consolidation rules**: (a) shared-check mechanical rule first — "*If the fix for each finding in the group is adding the SAME named check … consolidate into ONE finding … The title generalises to the missing check, not the function name*" (interesting: 0xsimao's mitigation-preservation says the opposite direction for distinct mechanisms; drozer's rule is for *identical* fixes, so they compose); (b) "*Could one PR fix all of them?*" test; (c) keep separate only when fixes are genuinely independent.
11. **Canonical vulnerability vocabulary**: snake_case tags aligned with SWC/C4 taxonomy; "*paraphrasing … is NOT allowed. The vocabulary aligns with … what external scorers and graders expect*" — output-schema discipline for benchmark interoperability.
12. **Domain checklists with methodology blocks**: e.g., lending.md: "*trace: (a) which oracle is read, (b) whether staleness and decimal conversions are correct, (c) whether health-factor checks bracket every collateral-moving path … Test boundary states explicitly: fresh market, frozen asset, paused underlying, extreme utilization, and dust positions*"; LEND-2 interest accrual monotonicity ("*debt rounds up, supply rounds down*"); reentrancy.md RE-4 read-after-call ("*Any security-critical read after an external call must either be re-validated or moved before the call*").
13. **Size refusal policy**: >1MB refuse, >500KB warn — an explicit scope guard others imply but don't state.

### 6.3 Contradictions with other methodologies

- **Anti-FP stance is the polar opposite of 0xsimao's Info-inclusive reports** ("*his real reports carry many, and they are what protocol teams value*") and of monethic's verifier (which downgrades but keeps). drozer would move those same Info items to warnings or drop them outright.
- **Pattern-level only**: contradicts (and complements) every reasoning-first repo; it explicitly declines chain analysis that 0xsimao's composite-chains and sc-auditor's adversarial-deep lane make central.
- **Missing-nonReentrant DROP rule** conflicts with qs_skills (which flags guard coverage gaps) and Auditmos (reentrancy skill flags token-transfer reentrancy as High). drozer's justification — no in-scope callback token ⇒ speculative — is benchmark-calibration logic, not security logic.
- **Severity inflation guard** (drop "exploit requires specific off-chain setup drozer-lite cannot verify") vs sc-auditor's "carry forward as candidate, do not dismiss".

### 6.4 What it lacks

- No accounting model, no invariant extraction, no multi-step attack construction, no PoC, no judge/verifier stage beyond gates, no checkpointing.
- Single-pass, one model instance per cluster; no subagent parallelism (contrast Kann cluster subagents).
- Benchmark-tuned severity can under-rate real-but-contextual bugs; the 40%-promotion/severity-table approach is calibrated for *grading*, which is not always the same as *security coverage*.

### 6.5 Classification recommendation

**Specialized sub-skill (fast pattern scan) + reference material (provenance-cited checklist library) + validation mechanism (3 gates + severity table + consolidation).** Its checklists are the best-formatted pattern reference in the cluster (provenance + methodology + red flags per check); its severity table and weak-evidence floor belong in the unified judge as a calibration instrument alongside 0xsimao's gates.

---

## 7. `scv-scan` — Minimal Cheatsheet-First Auditor

### 7.1 Contribution summary

The smallest, cleanest repo: a 4-phase single-agent method (load cheatsheet → two-pass sweep → selective deep validation → report) backed by ~40 full reference files, each with the canonical five sections: **Preconditions, Vulnerable Pattern, Detection Heuristics, False Positives, Remediation**. Its value is the *document architecture*: two-tier knowledge (ambient cheatsheet + on-demand deep references) that maximizes coverage per token.

### 7.2 Most valuable techniques

1. **Cheatsheet-first loading**: "*Before touching any Solidity files, read `references/CHEATSHEET.md` in full … Internalize these patterns — they are your detection surface for the sweep phase. Do NOT read any full reference files yet.*" Ambient awareness without context bloat.
2. **On-demand validation**: "*Read the full reference file … Read it now — not before … Walk through every Detection Heuristic step against the actual code … Check every False Positive condition. If any false positive condition matches, discard the finding and note why.*"
3. **Two-pass sweep**: Pass A syntactic grep (each cheatsheet entry ships `Grep-able keywords`, e.g. `extcodesize`, `.code.length`, `isContract`); Pass B structural/semantic ("*This pass catches vulnerabilities that have no reliable grep signature*").
4. **The five-section reference format** — the best detector-documentation standard in the cluster (its reentrancy.md enumerates cross-function, cross-contract, read-only preconditions and hidden-callback heuristics — `_safeMint`, `_safeTransfer`, ERC777/1155 hooks).
5. **Cross-reference rule**: "*one code location can match multiple vulnerability types … read and validate against each*" + "*A single line can be vulnerable to reentrancy AND unchecked return value.*"
6. **Version-aware checking**: "*Always check `pragma solidity` — many vulnerabilities are version-dependent (e.g., overflow is checked by default in ≥0.8.0)*"; also echoed in monethic's verifier rejection criteria.
7. **Precision-over-recall philosophy**: "*A shorter report with high-confidence findings is more valuable than a long one padded with maybes.*" — the clearest statement of the FP-cost thesis, later operationalized by drozer-lite.
8. **Hidden-call tracing principle**: "*Trace across boundaries. … Hidden external calls (safe mint/transfer hooks, ERC-777 callbacks) are as dangerous as explicit `.call()`.*"

### 7.3 Contradictions with other methodologies

- None structural; its FP-first stance aligns with drozer-lite/monethic and mildly conflicts with 0xsimao's "include Info, never drop leads" and sc-auditor's "carry candidates forward".
- Its single-pass, no-orchestrator design is the floor of the cluster's complexity spectrum — an intentional trade-off that the unified skill should absorb as its "quick scan" mode.

### 7.4 What it lacks

- Everything beyond pattern validation: no accounting model, no orchestration/judging/dedup, no tools, no severity calibration beyond one-line definitions, no confidence field, no checkpointing.

### 7.5 Classification recommendation

**Reference material + validation mechanism template.** Adopt its two-tier document format as the *mandatory standard for authoring all detector/reference docs* in a unified skill (every pattern must have Preconditions / Vulnerable Pattern / Detection Heuristics / False Positives / Remediation), and its cheatsheet-first sweep as the default Phase-1 broad scan.

---

## 8. `qs_skills` — Single-Dimension Plugin Suite + Blue-Team Release Gate

### 8.1 Contribution summary

Nine plugins: state-invariant-detection, reentrancy-pattern-analysis, signature-replay-analysis, oracle-flashloan-analysis, behavioral-state-analysis (lightweight BSA orchestrator), input-arithmetic-safety, dos-griefing-analysis, proxy-upgrade-safety, and **defender** (blue-team release-gate). Each plugin is a deep single-dimension taxonomy with detection algorithms, variant tables, severity matrices, and **"Rationalizations to Reject"** lists. BSA orchestrates the others with engine-selection per contract type and tiered output depth.

### 8.2 Most valuable techniques

1. **State-invariant detection algorithm** (unique in the cluster as a *procedure*): five relationship types (sum `totalSupply = Σ balance[i]`, difference `totalFunds = available + locked`, ratio `k = reserveA × reserveB`, monotonic, synchronization); **co-modification clustering** (`CoMod(A,B) = |functions modifying both| / |functions modifying either|; > 0.6 → related`); delta-pattern inference; then per-function before/after invariant testing: "*If I(stateA, stateB) = True AND I(stateA', stateB') = False: → F is VULNERABLE*" with temporal filtering for persistent violations. This is the mechanical version of 0xsimao's money-map asymmetry table — worth keeping as a *tool/algorithm* spec.
2. **Dual-layer severity integration**: Layer-1 guard analysis × Layer-2 invariant break → combined severity matrix ("*Missing Guard + Breaks Invariant → **CRITICAL***").
3. **Reentrancy 5-variant taxonomy** incl. **transitive reentrancy**: "*Build transitive call graph … For each call chain A → B → ... → X: If X can call back to any contract in the chain → TRANSITIVE REENTRANCY*" — the only repo that formalizes multi-hop reentrancy.
4. **Rationalizations to Reject** (every plugin ships them) — the best compact anti-FP-heuristics lists, e.g.: "*\"We use `transfer()` so reentrancy is impossible\" → EIP-1884 changed gas costs; `transfer` is no longer considered safe*" ; "*\"It's just a view function\" → Read-only reentrancy can manipulate prices and oracles in third-party contracts*" ; "*\"State is updated right after the call\" → \"Right after\" is too late.*"
5. **Signature trust model + 5 replay types**: "*A signature proves … For this to be secure, the signature must be: 1. Bound to context … 2. Used exactly once … 3. Time-limited … 4. Correctly verified*" — with same-chain, cross-chain, cross-contract, nonce-skip, expired-signature replay types.
6. **Oracle trust hierarchy (Level 1-5)** and **Oracle Dependency Map**: tree from `borrowLimit()` → `getCollateralPrice()` → `latestRoundData()`, annotating each read's risk (`getReserves()` = CRITICAL flash-loan-manipulable; `balanceOf(address(this))` = CRITICAL donation attack; `slot0()` = CRITICAL single-block manipulable).
7. **BSA token-budget rules** — the only repo that explicitly budgets context: "*Cap Phase 1 output to ≤30 lines per contract … PoC generation only for Critical and High … Combine phases in output — don't repeat findings … If a dimension has no attack surface … say \"N/A\" and move on*" — plus engine selection matrix (ETE/ACTE/SITE) by contract type.
8. **Input-arithmetic statistics framing**: "*input validation failures (the #1 direct exploitation cause at 34.6% of all contract exploits)*" — motivating each lens with a measured frequency (same pattern in signature plugin: 19.63% replay rate).
9. **DoS 7-class taxonomy** including 63/64 insufficient-gas griefing, storage bloat, timestamp griefing, selfdestruct force-feeding, push-vs-pull — the broadest DoS class list in the cluster.
10. **Proxy 5-class taxonomy**: storage layout collision, uninitialized implementation, selector clashing, delegatecall context, upgrade path safety — with the delegatecall storage-model diagram.
11. **Defender's release-gate discipline**: "*Evidence first. Only report findings from: contracts, deploy scripts, CI workflows, dependency manifests, configs / address books, tests / fork scripts, docs / runbooks*" and Detection-vs-Policy separation; strict execution order (classification → defence pass → severity → verdict); reference packs (finding-catalog, severity-model, evidence-query-playbook). Only repo covering CI/CD, signer opsec, and deploy-script drift as *security* surface.

### 8.3 Contradictions with other methodologies

- **Claimed statistics are unverifiable** ("19.63% of signature-using contracts", "34.6% of all contract exploits") — no citation; contrast drozer-lite's per-check provenance discipline.
- **Type-based engine selection** (BSA) contradicts 0xsimao's universal accounting-first stance ("*When the target has little accounting … keep the money map short, and go straight to your lens*" is 0xsimao's compromise; BSA skips ETE entirely for utility contracts).
- **Severity table** (read-only reentrancy HIGH, callback HIGH) is more aggressive than Auditmos' tiering for the same classes and much more aggressive than drozer's DROP rules.
- Defender's "blue-team" findings overlap sc-auditor's `config_dependent`/`design_tradeoff` categories but would be rejected by 0xsimao's "admin doing admin things" rule unless a concrete mechanism is named — Defender is intentionally a different product (release gate, not exploit hunt).

### 8.4 What it lacks

- No cross-plugin dedup/judge/orchestration beyond BSA's light engine routing; no tools/PoC; no checkpointing; no accounting-model builder of its own (state-invariant is the closest); EVM/Solidity-only.
- Plugin depth varies (some are taxonomy-heavy, procedure-light); no report standard shared across plugins.

### 8.5 Classification recommendation

**Specialized sub-skills + reference material.** Fold each plugin into the unified skill as: (a) lens content for reentrancy/signature/oracle/DoS lanes, (b) an *algorithm spec* for automated invariant inference, (c) Defender as a separate optional release-gate stage. Their "Rationalizations to Reject" lists are the best seeds for hard-negatives docs.

---

## 9. `monethic-maia` — Multi-Platform Batched Detector Engine (MAIA)

### 9.1 Contribution summary

The most production-shaped engine: 6-phase pipeline (Bootstrap → Recon → three analysis passes → batched detector rounds + generalist → Adversarial Verifier → Report Writer) across EVM (95 detectors / 20 categories), Move-Aptos (49/11), Move-Sui (48/11), with NUCLEAR cross-platform mode, a **formal detector-format specification** (`maia-detector.md`), keyword→rule routing table, output-budget policy, progress protocol, and severity policy.

### 9.2 Most valuable techniques

1. **The detector format spec** — the best KB-authoring standard in the cluster: "*One invariant per detector … Patterns must be concrete. Every pattern includes compilable (or near-compilable) code showing both the vulnerable and fixed versions. Detection steps are mechanical … Counter-evidence is specific … Severity reflects worst-case realistic impact*" — with exact field schemas (CL-ID, rule-ID, severity ranges like `medium-critical`, vulnerable/fixed blocks, Detect imperatives, Remediation).
2. **Three-layer KB**: full category files (CAT-*.md), compact **rulepack.md** entries ("*Trigger idea: … Counter-evidence: What a secure implementation looks like — what negates the finding*"), and **checklist_router.md** keyword→rule-ID table (`ecrecover` → EVM-CRYPTO-SIG-01; `slippage, deadline, minAmountOut` → EVM-DEX-SLIP-01). This gives both context-rich and token-cheap views of the same knowledge — the same two-tier idea as scv-scan, applied to a 192-detector KB.
3. **Sink-first deep sweep** (independent of detectors): "*Identify high-risk sinks first … Trace backwards from each sink: Who can reach it, what preconditions are needed, what state is affected*" with a platform-specific sink list (`call/delegatecall` w/o guards, `selfdestruct`, `tx.origin` auth, unchecked `ecrecover`, unprotected `initialize()`, slot collisions, flash-loan callbacks without caller validation, unchecked low-level call returns). Findings cross-reference and reinforce detector output.
4. **Evidence map stage**: build call graph, access-control signals, and state patterns before any detector runs; batched detector rounds receive recon + packed source + evidence map + deep-sweep results together — the closest analog to 0xsimao's bundle design at engine scale.
5. **Adversarial verifier with FP-first presumption**: "*Each finding begins with the presumption: \"This is likely a false positive unless local evidence proves exploitability.\"*" — isolated review ("*No cross-finding memory … Input limited to finding payload and relevant code excerpts only*"), 5 verification steps (references, attack path, scope, mitigations, dedup), universal + **platform-specific rejection criteria** ("*Reentrancy claim but checks-effects-interactions pattern followed AND/OR `nonReentrant` modifier present … Overflow claim but Solidity >= 0.8.0 and code is NOT in `unchecked` … Storage collision claim but ERC-7201 namespaced storage is used … Uninitialized proxy claim but `_disableInitializers()` is called*"). These rejection lists are themselves a compact modern-Solidity FP encyclopedia.
6. **Three-outcome triage**: `false_positive` / `valid` / `valid_downgraded`, with a **severity policy** for downgrades: "*Downgrade only when exploitability or impact is materially constrained by observed guards. Never downgrade without quoting concrete local evidence*" + confidence split (≥0.75 high-confidence else needs-manual-review).
7. **Output budget policy**: terse/normal/debug modes with per-stage terminal line budgets; `*.min.json` artifacts with max field counts (checklist item 5, finding 12); "*Report quality floor … every finding must keep: clear exploit impact (one line), concrete evidence pointer (file + line + short signal), actionable fix (one line), confidence and decision outcome.*"
8. **Progress protocol**: stage IDs, JSONL heartbeat events with counters, minimum heartbeat cadence (3s) — the only repo that treats long-run observability as a first-class requirement.
9. **Generalist round**: a full-spectrum first-principles pass that "*does not rely on checklist templates*" runs alongside detectors — mirroring 0xsimao's claim that checklists alone underfind; the generalist's minimum-coverage checklist doubles as an EVM baseline (auth, reentrancy variants, token handling, oracles).
10. **Mode ladder**: recommended / ALL / NUCLEAR / custom-categories — with honest disclosure that NUCLEAR has "*high FP rate*" (cross-platform pattern matching).

### 9.3 Contradictions with other methodologies

- **FP-first verifier vs drozer's Gate C**: monethic presumes false-positive and needs local evidence to keep a finding; drozer-lite adds an anti-self-invalidation gate because pattern matchers over-reject. These are the two poles of the verification dial; a unified skill should run them in sequence (drozer-style severity floor at generation, maia-style adversarial review at verification).
- **`medium-critical` severity ranges** vs discrete scales everywhere else; maia resolves at downgrade time using its policy — pragmatic but incompatible with sc-auditor's fixed enums and drozer's uppercase enums.
- **Verifier is isolated from full context** (finding + excerpt only) — opposite of sc-auditor's skeptic, which gets the whole SystemMap. Isolation prevents bias but can miss cross-contract guards; sc-auditor's skeptic catches those and demands proof.
- **Dedup by `(rule_id, file, line, title)`** is shallower than 0xsimao's `Contract|function|bug-class` + mechanism preservation and sc-auditor's fix-shape key.
- **No user gates mid-audit** (mode choice only) vs sc-auditor's blocking gates; NUCLEAR cross-platform matching vs drozer's language-translation discipline (maia runs Move detectors against EVM code — admitted FP risk).

### 9.4 What it lacks

- No PoC/fuzzing/proof layer (verifier is pure review); no accounting-model synthesis (recon is roles/entry-points/state, not a money map with asymmetry tables); no checkpointing/resume protocol for long runs; no benchmark calibration visible in-repo (drozer-lite has it; maia doesn't).

### 9.5 Classification recommendation

**Core methodology (pipeline skeleton for large multi-platform audits) + reference material (192-detector KB + detector-authoring spec) + validation mechanism (adversarial verifier).** Its detector format spec + rulepack/router structure is the recommended way to organize *all* pattern knowledge harvested from the other repos; its verifier rejection lists and severity policy are reusable judge components.

---

## 10. Cross-Repo Synthesis

### 10.1 Contradiction map (design axes where the repos disagree)

| Axis | Positions | Implication for a unified skill |
|---|---|---|
| **Privileged-role findings** | Auditmos: downgrade to M/L with carve-outs. sc-auditor: discard (good faith) except 4 exception classes. 0xsimao: exclude "admin doing admin things"; report only with concrete mechanism + unbounded parameter. drozer: cap at MEDIUM as centralization. | Adopt sc-auditor's 4 exceptions as the canonical rule, 0xsimao's "named mechanism required" as the evidence bar, Auditmos' carve-out lists as per-domain guidance. |
| **FP/verification philosophy** | drozer Gate C (anti-self-invalidation) and precision-over-recall vs monethic FP-first presumption vs 0xsimao "UNCERTAIN = ALLOWS" + include Info + never drop leads vs sc-auditor carry-candidates-forward. | Stage the dial: generation-time severity floor (drozer) → independent adversarial verify with inversion mandate (sc-auditor/maia) → judge with burden-of-proof (sc-auditor). Emit leads/Info in a separate section (0xsimao/Kann below-threshold). |
| **Severity taxonomy** | 0xsimao: no Critical, Info included. sc-auditor/maia: Critical + GAS. drozer: uppercase enums, LOW/INFO filtered. Auditmos: inconsistent per-skill criteria (%, actor-based). | Standardize: Critical/High/Medium/Low/Info (no GAS findings — route to advisory), with 0xsimao's 4 gates + drozer's severity table + Auditmos' numeric bands reconciled as "loopable ⇒ escalate". |
| **Proof burden** | sc-auditor: executable PoC/fuzzer required for "verified". 0xsimao: numbered numeric attack path. maia: verifier verdict only. drozer: exploit sentence + severity table. | Tier statuses: `verified` (artifact), `confirmed` (numeric path + 2 independent lanes), `candidate`, `discarded` — sc-auditor's status model, with 0xsimao's independence count as evidence. |
| **User gates** | sc-auditor blocking gates; all others autonomous (maia mode-choice only; 0xsimao prints summary, no wait). | Make gates optional (`--interactive`); checkpoint before each gate so both modes share the state machine. |
| **Orchestrator role** | sc-auditor: orchestrator never audits. 0xsimao: orchestrator builds the money map itself. | Compose: orchestrator builds the model (0xsimao) but delegates all hunting/verification and forwards minimal per-phase context (sc-auditor). |
| **Where pattern knowledge lives** | maia: 192 detectors w/ authoring spec. drozer: provenance-cited checklists. scv-scan: 5-section references. Kann: real-finding clusters. Auditmos: domain skills. | Consolidate into maia's detector format; require scv-scan's 5 sections + drozer's provenance line per pattern; tag each detector with Kann-style real-world examples. |
| **LOW/INFO handling** | drozer: filter to warnings, drop on schema mismatch. 0xsimao: include Info, never drop leads. Kann: below-threshold section. | Emit a mandatory `warnings[]`/leads channel (drozer) but never *silently* drop (0xsimao); document the schema rule so graders and clients both get what they need. |
| **Read-only reentrancy severity** | Auditmos High (price-manipulation exploit), qs_skills HIGH, drozer DROP without in-scope callback token. | Keep as HIGH-conditional: require the concrete downstream reader (which contract consumes the stale view) before rating — qs_skills' transitive detection supplies the reader; drozer's in-scope rule supplies the gate. |

### 10.2 Focus-area coverage map (best sources per requested area)

- **Multi-pass auditing**: sc-auditor (state machine, checkpoints, 5-6 lanes + ATTACK + VERIFY + judge) and 0xsimao (12 independent lenses + single-pass judge). Best pass structure: 0xsimao-style parallel independent lenses, sc-auditor-style phase gates + checkpoints.
- **Accounting analysis**: 0xsimao-ai is definitive (drift taxonomy, asymmetry table, LastOut test, tracked totals) with qs_skills state-invariant algorithm as the mechanical complement and Kann state-hunter for storage-layer losses.
- **Liquidation math**: Auditmos (5 skills: reward decimals, fee priority, bonus vs collateral cap, bad-debt clearing, LTV gap, cherry-picking) + 0xsimao liquidation-solvency lens (health vs liquidation formula disagreement, accrue-before-judge, counterpart updates) + drozer LEND-1..5 (HF bracket after mutation, interest monotonicity, oracle staleness at liquidation, flash-loan borrow).
- **Oracle analysis**: Auditmos audit-oracle (11 patterns incl. depeg, sequencer, circuit breakers) + qs_skills oracle trust hierarchy + drozer ORACLE-1..3 (per-asset heartbeat, reader-matrix consistency) + scv-scan/sc-auditor token-oracle lane.
- **Reentrancy**: qs_skills 5-variant + transitive taxonomy (most complete) + Auditmos 4 patterns + drozer RE-1..5 + sc-auditor callback-liveness lane + maia verifier's CEI/nonReentrant rejection criteria.
- **Signature verification**: Auditmos audit-signature + qs_skills 5 replay types + trust model + maia rejection (nonce/domain chain-id) + scv-scan ecrecover/malleability references + drozer signature profile (permit front-run, router identity).
- **State validation**: Auditmos audit-state-validation + Kann state-hunter CAT-1..5 + qs_skills input-arithmetic (zero address/amount, array lengths) + sc-auditor semantic-consistency lane.
- **Checklist design**: maia detector spec + rulepack/router (authoring) + drozer provenance-per-check (calibration) + scv-scan 5-section format (structure) + Auditmos per-skill false-positive lists (content).
- **Detector taxonomies**: drozer 110-check universal + Kann clusters + maia 20-category EVM tree + qs_skills variant tables.
- **Report formats**: 0xsimao (mechanism-bearing titles, Description+Mitigation, leads section, protocol summary header) + Kann (numbered attack scenario, diff-required fixes, below-threshold) + sc-auditor (5 status tiers incl. Discarded-with-reasoning) + Auditmos (gas/cost analysis, token compatibility matrix) + maia (confidence + evidence pointer + one-line impact floor).
- **Reasoning-depth mechanisms**: 0xsimao markers ([Model]/[Why]/[Defeat]/[LastOut], saturation sweep, named-victim requirement, concrete arithmetic requirement per lens) + sc-auditor DA 6-dimension scoring with mandatory evidence + dry-run + semantic tension analysis + qs_skills rationalizations-to-reject.

### 10.3 Shared gaps across all repos

1. **No repo validates detector knowledge against a live benchmark in-skill** except drozer-lite (provenance) and Kann (clusters); the others assert coverage. A unified skill should carry regression cases (maia has `tests/regression_cases.md` stubs) and require every new detector to cite a real finding.
2. **Context-window engineering is uneven**: only maia (output budget, min.json), BSA (token rules), Kann (40% promotion), drozer (size refusal), and 0xsimao (bundle + exclude pattern) address it explicitly; sc-auditor relies on checkpoints. A unified skill needs all of these.
3. **Resumption**: only sc-auditor checkpoints; long audits need it as a first-class feature.
4. **Cross-language translation** is only systematic in drozer-lite (concept table) and maia (platform variants); the EVM skills ignore it.
5. **Proof execution** is only in sc-auditor (MCP fuzzers/PoC); everyone else narrates. Unified skill should make proof optional-but-tiered rather than required (sc-auditor's benchmark mode shows the pattern).
6. **Idempotency/determinism**: no repo defines how the same codebase re-audited twice should be diffed or compared (regression re-checks exist only as 0xsimao's integration-assumptions bullet "re-check that previously-reported issues … were actually fixed").

### 10.4 Recommended unified-skill architecture (synthesis)

1. **Phase 0 — Readiness (optional, from cdsecurity-skills)**: coverage/hygiene/docs score, SECURITY.md + KNOWN_ISSUES.md generation. Feeds the docs-as-specification step.
2. **Phase 1 — Recon & Model**: 0xsimao money map (assets, tracked totals, asymmetry table, 5-15 invariants, lifecycles, cohorts) merged with sc-auditor SystemMapArtifact (write sites, call sites, value-flow edges, config semantics) — one artifact, both views; user gate optional.
3. **Phase 2 — Broad sweep (cheap)**: scv-scan cheatsheet-first grep + semantic pass; drozer-lite profile auto-detection and severity-table triage as the FP floor; Kann 40%-batching to load the maia-formatted detector KB.
4. **Phase 3 — Independent parallel lenses**: 0xsimao's 12 lenses, each seeded with Auditmos/qs_skills/drozer domain content, plus Kann state-hunter as lens 13 and qs_skills state-invariant algorithm as tool input; mandatory markers ([Model]/[Why]/[Defeat]/[LastOut]); FINDING/LEAD schema with group_key + independence count.
5. **Phase 4 — Attack & proof**: sc-auditor ATTACK per hotspot (Quick Veto → 6-dimension DA → exploit sketch with numeric_example + same_fix_test); proof tiered (Foundry PoC/fuzzer when available, else numeric path).
6. **Phase 5 — Verification**: sc-auditor skeptic inversion + maia adversarial verifier rejection criteria; judge "prove-it-or-lose-it" conflict matrix; statuses verified/confirmed/candidate/discarded with DA-chain reasoning.
7. **Phase 6 — Dedup & report**: 0xsimao dedup hard gates (function isolation, mechanism/mitigation preservation, completeness) + drozer shared-check consolidation for identical fixes; report = 0xsimao format (mechanism-bearing titles, protocol summary, Description+Mitigation, Unverified leads) + Kann numbered attack scenarios + Auditmos cost/gas analysis where relevant + maia quality floor (impact/evidence/fix/confidence one-liners).
8. **Cross-cutting**: sc-auditor checkpoint manifest; maia output budget + progress protocol; drozer canonical severity enums; severities: Critical/High/Medium/Low/Info with 0xsimao gates + drozer table + loop-rule ("a rounding error is only Low if it cannot be looped").

### 10.5 Final classification table

| Repo | Core methodology | Specialized sub-skill | Reference material | Tool integration | Validation mechanism | Judge mechanism |
|---|---|---|---|---|---|---|
| skills (Auditmos) | — | ★★★ (14 domain skills) | ★★★ (checklists, report templates, always-checklist) | — | ★★ (access-control-first triage, FP lists) | ★ (severity tiers) |
| 0xsimao-ai | ★★★ (money map + 12 lenses) | — | ★★★ (lens files) | — | ★★★ (4 severity gates) | ★★★ (dedup gates, calibration) |
| sc-auditor | ★★★ (state machine pipeline) | ★★ (hunt lanes) | ★★ (attack vectors, hard negatives) | ★★★ (slither/aderyn/fuzzers/PoC MCP) | ★★★ (DA protocol, skeptic) | ★★★ (judge matrix, conflict resolution) |
| Kann | ★ (2-lane pipeline) | ★★ (state hunter) | ★★ (cluster corpus) | — | ★★ (3-check FP gate) | ★★ (dedup, below-threshold) |
| cdsecurity-skills | — | ★★★ (audit readiness) | ★★ (SECURITY.md/scope templates) | ★★ (scanner wiring) | ★★ (scored rubric) | — |
| drozer-lite | — | ★★★ (pattern scan, multi-language) | ★★★ (provenance checklists) | — | ★★★ (3 gates, severity table, weak-evidence floor) | ★★ (consolidation rules) |
| scv-scan | — | ★★ (minimal scan mode) | ★★★ (5-section reference standard) | — | ★★ (heuristic walk + FP check) | — |
| qs_skills | ★ (BSA) | ★★★ (9 plugins, incl. defender) | ★★★ (taxonomies, rationalizations) | — | ★★ (invariant algorithm) | ★ (severity matrices) |
| monethic-maia | ★★★ (6-phase engine, multi-platform) | — | ★★★ (192 detectors + authoring spec) | — | ★★★ (adversarial verifier) | ★★ (severity policy, dedup) |

**Bottom line:** the highest-value synthesis is *0xsimao's reasoning model + sc-auditor's verification machine + Auditmos/qs_skills/drozer/maia content + maia's KB format + scv-scan's doc format + drozer's severity calibration + cdsecurity's readiness stage*, unified under one state machine with checkpoints, output budgets, and a tiered proof bar.

---

## Appendix — Highest-Value Verbatim Blocks to Preserve in a Unified Skill

1. **0xsimao money-map invariant template**: "*Invariants — 5–15 statements that must always hold, in the form `sum(user claims) <= actual balance`, `totalX == Σ userX`, `index only increases`, `every credited unit is debited exactly once`.*"
2. **0xsimao drift table** (6 rows: missing write / wrong write / mistimed / wrong party / untrustworthy input / unreachable state) — quoted in full in §2.2.
3. **0xsimao severity gates**: "*One `BLOCKS` on the critical path kills the finding — reject it, do not demote it*" and "**`UNCERTAIN` counts as `ALLOWS`** — an unproven guard is not a guard."
4. **0xsimao calibration checks**: "*A rounding error is only Low if it cannot be looped. Check that first, always.*" and "*When genuinely torn between two severities, choose the lower and say why in one line. Over-claiming costs credibility, and credibility is the whole product.*"
5. **0xsimao dedup hard gates**: function isolation (NEVER merge across `function:`), mechanism preservation, mitigation preservation (Option A/B), completeness gate ("*Completeness: N unique (Contract, function) in raw, N covered in final.*").
6. **sc-auditor DA decision rules**: "*At least one -3 AND total <= -6 → INVALIDATED … Partial mitigations DEGRADE confidence. They NEVER dismiss alone.*"
7. **sc-auditor privilege rule**: good faith + authority propagation / composition failures / flash-loan governance / config interaction.
8. **sc-auditor judge**: "*The disagreeing party bears the burden of proof. No proof = your claim fails.*"
9. **sc-auditor dedup key**: "*(contract, function, state_vars, invariant, fix_shape) … Two findings with the same root cause but different fix shapes are distinct.*"
10. **drozer weak-evidence floor**: cap at LOW when loss depends on off-chain payload construction, admin-set-later config, unobservable ordering, or callbacks on callee types outside the whitelist.
11. **drozer shared-check consolidation**: "*If the fix for each finding in the group is adding the SAME named check … consolidate into ONE finding … The title generalises to the missing check, not the function name.*"
12. **scv-scan five-section reference format**: Preconditions / Vulnerable Pattern / Detection Heuristics / False Positives / Remediation, loaded on-demand only.
13. **maia verifier presumption**: "*Each finding begins with the presumption: \"This is likely a false positive unless local evidence proves exploitability.\"*" plus platform rejection criteria (CEI+nonReentrant present, ≥0.8 outside unchecked, ERC-7201 namespaced storage, `_disableInitializers()` present).
14. **maia detector spec**: one invariant per detector, mechanical Detect steps, specific counter-evidence, vulnerable+fixed compilable patterns, rulepack trigger/counter-evidence, keyword→rule router.
15. **Kann triage tiers**: Skip / Borderline ("*promote only if you can name the exact function AND the exact line number AND describe the exploit in one sentence*") / Survive; 40%-match promotion gate for KB batching.
16. **qs_skills transitive reentrancy**: "*For each call chain A → B → ... → X: If X can call back to any contract in the chain → TRANSITIVE REENTRANCY*" and the Rationalizations-to-Reject lists.
17. **Auditmos always-checklist** (CEI, cross-function/read-only reentrancy, fee-on-transfer, rebasing, callbacks, zero-transfer reverts, pausable tokens, decimals, two-step ownership, roles, pause, timelock) as the universal pre-flight.
18. **cdsecurity SECURITY.md/KNOWN_ISSUES.md templates** and the 90% branch-coverage readiness gate.
