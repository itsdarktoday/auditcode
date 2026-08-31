# Cluster 4: Non-EVM Chains & Static-Analysis Tooling — Deep Extraction Report

**Scope:** 12 repositories under `/home/nishan/ultimate-web3-security/sources/`:
`move-auditor`, `move-auditor-skills`, `sui-move-skill`, `SUIZERO`, `safe-solana-builder`, `solana-token-extensions-security`, `solskill`, `zk-skills`, `weasel`, `GPTScan`, `hydration-node`, `openzeppelin-skills`.

**Method:** SKILL.md, README, methodology docs, agent prompts, attack-vector catalogs, judging/validation references, and tool sources were read in full or representative depth. Quotes are verbatim with file attribution. Per-repo sections cover: (1) contribution, (2) most valuable techniques with concrete quotes, (3) contradictions, (4) gaps, (5) classification recommendation (core methodology / specialized sub-skill / reference material / tool integration / validation mechanism / judge mechanism / build-time guard). A cross-repo synthesis — including what transfers from EVM methodologies and what is chain-specific — closes the report.

---

## Executive Summary

This cluster contains the strongest non-EVM security-knowledge base in the corpus, plus the static-analysis tooling that complements it. Three tiers emerge:

**Tier 1 — core chain-specific audit methodologies:**
- **`move-auditor`** (Panther Audits, v3.12) — the most complete Move/Sui/Aptos audit skill: 180+ patterns (COMMON / SUI-01..46 / APT-01..25 / DEFI-01..95), an 8-phase workflow, an anti-false-positive engine (confidence gates, evidence chains, FP catalog, self-hallucination protocol), and uniquely deep Sui runtime knowledge (stale-package surface, PTB repeated-call bypass, `max_move_object_size`, dynamic-field cache ceiling, abort-before-checkpoint deadlock).
- **`zk-skills`/`circom-auditor`** — the strongest ZK-circuit audit skill: 48 real-bug-grounded attack vectors organized by *code shape*, a 17-agent delegated workflow, a mandatory "mental tool protocol" (Feynman/Socratic/Inversion markers), and a judge tuned to the R1CS threat model (soundness/completeness/privacy). Its core doctrine — *"Circom is declarative … the question is never 'what does this line do?' It is always 'what does the constraint system still ALLOW?'"* — is the single best transfer of adversarial thinking to ZK.
- **`safe-solana-builder`** — the only Solana security skill: 31 sections of framework-agnostic rules distilled from real audits (CPI reload, PDA bumps/seeds, duplicate-mutable-account attacks, reward-debt settlement, Token-2022 extension whitelisting, BPF 4096-byte stack frames), plus Anchor/native-Rust/Pinocchio/LiteSVM references and a worked example with a 31-rule checklist.

**Tier 2 — specialized sub-skills and judge/validation machinery:**
- `move-auditor-skills` (parallel 8/9-agent orchestration, 4-gate judging, 143 attack vectors) and `hydration-node` cl0wdit (same lineage applied to Substrate, with a known-false-positive catalog) are the best *judge + orchestration* patterns for non-EVM chains.
- `sui-move-skill` contributes the best **historical-regression-matrix** workflow and an 8-topic check router with mandatory pairings.
- `solana-token-extensions-security` is the best Token-2022 pitfall reference (extension-by-extension exploit shapes + Alice/Bob PoC framing + 0–1 confidence scores).

**Tier 3 — tooling and reference:**
- `SUIZERO` (bytecode-level Sui Move analyzer, 330+ claimed detectors incl. "Phantom Authorization" and "Capability Theater"), `weasel` (MCP-wrapped Slither-style analyzer with PoC/validate/report skills), `GPTScan` (ICSE'24 GPT+static-analysis hybrid), `openzeppelin-skills` (library-first secure development + Sui integration review), `solskill` (Cyfrin dev standards / BattleChain battle-testing).

**Biggest cross-cutting findings:**
1. **The accounting-desync/asymmetry frame transfers perfectly to Move, Solana, and Substrate** — value moves, a tracked total must move with it, and the bug is the missing/one-sided/mistimed write. It appears in move-auditor (semantic-gap types `SYNC_GAP`/`DUAL_SOURCE_METRIC`), safe-solana-builder (§21 reward-debt, §3.4 lamport invariant, §22 vault paths), and hydration cl0wdit (cross-pool LP share theft "confused deputy").
2. **The 4-gate judge (refutation → reachability → trigger → impact) with concrete-vs-speculative refutation discipline is a shared, battle-tested lineage** (move-auditor-skills, zk-skills, hydration cl0wdit — all pashov v2-derived) and should be the unified judge mechanism.
3. **The biggest chain-specific divergence is the meaning of "reentrancy."** move-auditor's FP catalog says "Move has no reentrancy (no dynamic dispatch), no delegatecall … The Solidity mental model does not transfer"; SUIZERO ships SUI-REEN-001..004 reentrancy detectors; move-auditor's own aptos-patterns documents APT-21 *function-value reentrancy* (Move 2.2+ closures). A unified skill must keep all three truths separate: no EVM-callback reentrancy on Sui, PTB state-inconsistency reentrancy on Sui, and closure-callback reentrancy on Aptos ≥2.2.
4. **Sui upgrades create a threat model no EVM skill has:** all historical package versions remain executable forever (SUI-23, Scallop incident), so bug fixes don't deprecate old code and immutable-protocol + upgradeable-dependency = permanent brick (SUI-22). move-auditor's version-gate ritual is the Move analog of "old proxy implementations remain callable," generalized.
5. **Several suites contradict on severity philosophy** (admin-origin latent DoS, saturating arithmetic, capability `store` ability) — detailed in the contradictions section; most resolve via the known-FP/known-good pattern catalogs.

---

## 1. `move-auditor` (Panther Audits) — Move/Sui/Aptos Audit Skill v3.12

### 1.1 Contribution

The flagship Move security skill. 515-line `SKILL.md` orchestrating an **8-phase workflow** (assessment → codebase map → structured scan → DeFi checks → semantic-gap scan → cross-module scan → verify & triage → report) over ~9,000 lines of reference material: `common-move.md` (chain-agnostic, sections 1–13), `sui-patterns.md` (SUI-01…SUI-46), `aptos-patterns.md` (APT-01…APT-25), `defi-vectors.md` + 9 `defi/*.md` deep dives (DEFI-01…DEFI-95), plus the anti-FP engine (`verification-policy.md`, `evidence-chains.md`, `confidence-gates.md`, `move-fp-catalog.md`, `checklist-router.md`, `semantic-gap-checks.md`). Signal-based routing loads only relevant checklists. Battle-tested: accepted findings against Sherlock Current Finance (#27/170+), OZ contracts-sui (PR #263 merged), $24k bug-bounty rewards; benchmark-driven (v3.4 "Anti-FP overhaul reduced false positive rate … ~25% FP rate" revealed by CurrenSui benchmark).

### 1.2 Most valuable techniques (verbatim)

1. **Chain/feature signal router** (`checklist-router.md`): keyword → file mapping (`sui::object` → `sui-patterns.md`; `borrow`/`collateral`/`health_factor` → lending files; `reward_per_share`/`accumulator` → staking + `semantic-gap-checks.md`) with escalation rules, e.g. *"If the chain is Sui AND any shared object exists, run the SUI-23 stale-package detection ritual … Treat every historical package version as live attack surface — bug fixes do NOT deprecate prior versions unless CURRENT_VERSION was bumped and migrate was run on every shared object."*
2. **The abort-before-checkpoint deadlock class (common-move 12.1, DEFI-86)** — flagged as the **"#1 missed bug class in Move audits"**: *"A periodic accounting function … performs arithmetic that can abort, and the state checkpoint (`last_update_time`, `cumulative_index`, `reward_per_share`) is written **after** the potentially-aborting line. If the arithmetic aborts, the checkpoint never advances. On the next call, the time delta is even larger, making the overflow worse — the function is permanently uncallable."* Every operation that touches the pool then reverts; liquidations freeze; bad debt accumulates.
3. **Multiply-before-divide overflow in fixed-point helpers (DEFI-85)** with a concrete threshold table — *"Token: USDC (6 decimals) → 500,000 USDC = 5e11 atomic units. Overflow at: time_passed_ms = U64_MAX / 5e11 = 3.69e7 ms ≈ 10.25 hours"* — plus the mandatory Fixed-Point Library Inspection Gate in Phase 3: *"Open every fixed-point helper, derive overflow bounds, compute threshold table, and apply the Recoverability Matrix. … Skipping this gate = missing permanent-deadlock bugs."*
4. **Admin-origin latent user DoS (12.2)**: *"Severity is based on **who is blocked and what is blocked**, not who created the initial configuration"* — never dismiss as "admin-only" when a routine admin config action later bricks permissionless user/liquidator paths.
5. **Uninitialized account index = full historical reward credit (DEFI-88)**: per-user `last_index` defaulting to 0 credits `current_index − 0`; *"the SDK … almost always calls a setter … masking the bug. The vulnerability only surfaces when someone bypasses the SDK … which is exactly the threat model on Sui because all historical package versions remain executable forever (see SUI-23, Scallop incident)."*
6. **PTB repeated-call limit bypass (SUI-28)**: *"close factor of 50% bypassed via 3 liquidation calls in one PTB, achieving 87.5% total liquidation"*; per-call limits must be enforced per-**transaction** (hot-potato snapshot, flag, or cumulative accumulator).

7. **Stale-package surface ritual (SUI-23)**: shared structs need `version: u64`; *every* `public`/`entry`/`public(package)` function taking `&T`/`&mut T` must assert `version == CURRENT_VERSION` **before any state read**; migration must be AdminCap-gated, wired into upgrades, and `CURRENT_VERSION` actually bumped — otherwise "a protocol that ships a fix without bumping the version has not deprecated the buggy old package — it has just added a second valid path."
8. **Check-vs-settlement value-basis divergence (DEFI-91/92)**: trace every value-moving action from the gating predicate to the settlement transfer; any price/rounding/units/fees difference is a candidate; *"a hard `assert!` … tying A to B then reverts … Because the liquidation queue retries the same item with the same inputs every cycle, the revert is deterministic and the account becomes **permanently unliquidatable**."* Four-axis table (Price / Rounding / Units / Fees) is directly reusable in EVM.
9. **Signatures verified against live policy instead of signing-time policy (DEFI-89)**: bind a `signer_policy_nonce` into the signed message and bump on every signer/threshold mutation — *"a request that was deliberately not executable when signatures were gathered … can silently become executable later after a routine policy update."*
10. **Self-trade value extraction on unhealthy margin accounts (DEFI-94)**: self-match protection comparing account IDs (not owner) lets one owner drain a leveraged account into a clean one; residual bad debt = `1 - risk_ratio / (1 + liquidation_bonus)`.
11. **Anti-FP engine** — `move-fp-catalog.md` §1 "Rationalizations to Reject" is the best single-page LLM-audit discipline list in the corpus: *"Move aborts on overflow (DoS, not silent corruption). DoS is only a finding if attacker profits from the abort"* (with the 12.1 warning appended); *"Move has no reentrancy (no dynamic dispatch), no delegatecall, no fallback functions, no storage collisions. The Solidity mental model does not transfer"*; *"Sui object ownership IS access control — if the function takes `&mut MyObject` (owned), only the owner can call it"*; *"On Aptos, `public fun` is NOT a transaction entry point … On Sui, `public fun` IS PTB-callable."*
12. **Confidence gating that caps severity** (`confidence-gates.md`): *"A finding at `needs_review` confidence can NEVER be rated High or Critical"*; `confirmed` requires 2+ signals from different categories; 8 signal types ranked 1–5 strength (code pattern → on-chain state).
13. **Evidence-source tagging with a mock-rejection rule** (`verification-policy.md`): `[CODE]`/`[TEST]`/`[PROD-SOURCE]`/`[PROD-STATE]` vs `[MOCK]`/`[DOC]`/`[EXT-UNVERIFIED]`; *"If a dismissal depends on `[MOCK]`, `[DOC]`, or `[EXT-UNVERIFIED]`, do not mark the finding DISMISSED."*
14. **Move trust-level table** (`evidence-chains.md`): owned object = owner-trusted, shared object = **untrusted**, function argument = untrusted, `clock::timestamp_ms`/TxContext = system-trusted — the Move analog of EVM msg.sender/msg.value trust classification.
15. **Kill questions + counterfactual-fix test** (Phase 7): *"Does my recommended fix change observable behavior?"*; *"Same value, different error code" is not a vulnerability — both produce transaction abort with identical user-facing outcome"*; *"For any function I claim 'reverts when it shouldn't' — what would it DO if it didn't revert?"*
16. **Root-cause dedup**: group by *"the single LINE OF CODE that would need to change, not by downstream effect"* — *"EMA/spot asymmetry" reported as tolerance bypass vs withdrawal blocking → SAME finding."*
17. **Known-good design patterns (DESIGN-L1..L4)** (`defi/defi-lending-design-patterns.md`): spot-for-seize/EMA-for-eligibility, flash-loan-keeps-accounting, block-borrows-when-cash<reserve, asymmetric divergence formulas — *"The burden of proof shifts when a pattern matches established protocol design. Instead of proving the code is safe, you must prove why the established pattern is unsafe in THIS specific context."*
18. **Cross-module interaction pairs** (Phase 6) — nine mandatory pair checks for lending. *"For any interaction pair where the answer is NO → report as HIGH."*
19. **Build & test log analysis (common-move §13)**: `sui move build`/`test`, grep `arithmetic error`, `abort code 4001`, `#[expected_failure]` anomalies — *"A test that passes with `#[expected_failure(abort_code = ...)]` is the developer **acknowledging** an abort exists."*
20. **Sui runtime hard limits most auditors don't know**: SUI-45 (`max_move_object_size` ~256KB — inline `vector`/`VecMap` fields grown permissionlessly brick *all* writes to the object; Tables don't count), SUI-46 (dynamic-field child cache = 1,000, **cumulative across PTB commands**; *"Never accept 'we are far under the gas cap' or a passing `sui move test` as evidence"*), SUI-21 (denylist enforced at validator level; receiving blocked only next epoch — bridge burn/mint gap).

### 1.3 Contradictions

- **vs. itself / SUIZERO:** FP-rationalization #5 denies reentrancy exists in Move, yet `aptos-patterns.md` APT-21 documents *function-value reentrancy* (Move ≥2.2 closures: *"a callback can re-enter the calling module via dynamic dispatch"*) and SUIZERO ships reentrancy detectors. Resolution: the skill's own SUI-02 (PTB state-inconsistency) is the real Sui analog — the denial must be read narrowly (no EVM fallback-callback reentrancy).
- **vs. move-auditor-skills:** capability abilities — move-auditor 1.2 says caps should have *"zero or only `drop` ability"*; move-auditor-skills V5 says `store` is FP when *"store required for legitimate purposes (e.g., storing in dynamic fields)"*. Both agree the fix is explicit transfer policy; the difference is default posture (deny `store` vs. allow-with-policy).
- **vs. sui-move-skill severity posture:** move-auditor caps `needs_review` at Medium and demands PoC for High/Critical; sui-move-skill requires *"keep well-supported medium, low, and informational security issues when they are grounded in code"* — complementary, but they disagree on how hard to push admin-origin/regression findings (see §3.3).
- **vs. EVM methodologies:** deliberately rejects several EVM axioms (reentrancy, unchecked-arithmetic-as-corruption, "public function = anyone can call"). A unified skill must route these per-chain rather than merge them.
- Dated future references ("Scallop, April 2026", "CurrentSUI") signal the catalog encodes incidents that may postdate readers' knowledge — a maintenance risk, not an error.

### 1.4 Gaps

- No tool integration (roadmap: *"Automated grep patterns for common Move anti-patterns"*, machine-readable artifacts — not yet shipped); no scripts, no Move Prover/spec templates despite mentioning them; no invariant-harness/fuzz guidance.
- Context-heavy: "always load" four files + chain file + DeFi files; no context-budget management for small models.
- Solana/other-chains explicitly out of scope ("When NOT to Use — … Rust/Anchor, EVM, TEAL, FunC").
- `sample-finding.md` and benchmarks are the only regression material; no automated regression suite.

### 1.5 Classification

**Core methodology (Move/Sui/Aptos)** — the unified skill's Move branch should be built on this, verbatim. Its anti-FP engine (confidence gates, evidence tags, FP catalog) and the DEFI-88/89/91/92/94 pattern family are **reference material reusable across all chains**.

---

## 2. `move-auditor-skills` (sanbir) — Parallel-Agent Sui Move Audit (v2 lineage)

### 2.1 Contribution

The multi-agent variant of Move auditing, "Built on the v2 packaging and workflow model from pashov/skills, then adapted for Move and Sui-specific security work." Orchestrates a parallelized audit: Turn 1 discover (find `.move` files, resolve references dir, version-check against remote), Turn 2 prepare (bundle source + agent instructions into `/tmp` files via `cat` — *"Do NOT inline file content into agent prompts"*), Turn 3 spawn **8 parallel agents** (vector-scan, math-precision, access-control, economic-security, execution-trace, invariant, periphery, first-principles) + Agent 9 (Sui protocol analysis, opus) in DEEP mode, Turn 4 single-pass dedup → 4-gate judge → report. Ships a 143-vector attack catalog (`attack-vectors-1..5.md`, D/FP format) and 8 protocol checklists (lending 14 items, AMM 10, vault 10, staking 10, bridge 9, governance 6, NFT/kiosk 8, upgrade safety 8).

### 2.2 Most valuable techniques

1. **Structured agent output with a dedup key**: *"`FINDING | module: Name | function: func | bug_class: kebab-tag | group_key: Module | function | bug-class`"* — and *"Every FINDING must have a `proof:` field — concrete values, traces, or state sequences from the actual code. No proof = LEAD, no exceptions."*
2. **Composite chains**: *"if finding A's output feeds into B's precondition AND combined impact is strictly worse than either alone, add 'Chain: [A] + [B]' at confidence = min(A, B)."*
3. **The 4-gate judge** (`judging.md`) — the cleanest formulation of the shared lineage: *"Gate 1 — Refutation: Construct the strongest argument that the finding is wrong … Concrete refutation (specific guard blocks exact claimed step) → REJECTED … Speculative refutation ('probably wouldn't happen') → clears, continue"*; Gate 2 reachability (shared vs owned objects), Gate 3 trigger (unprivileged actor, profit), Gate 4 impact.
4. **Single-pass protocol against endless re-litigation**: *"evaluate every relevant code path ONCE in fixed order (init → admin setters → core operations → deposit → withdraw → liquidate). One-line verdict per path: `BLOCKS`, `ALLOWS`, `IRRELEVANT`, or `UNCERTAIN`. Commit after all paths — do not re-examine. `UNCERTAIN` = `ALLOWS`."*
5. **Numeric confidence**: start at 100, deduct −20 partial path / −15 bounded impact / −10 specific-state; confidence ≥ 80 gets fix.
6. **Lead promotion rules**: cross-module echo, multi-agent convergence (promote at 75), partial-path completion.
7. **143 attack vectors in D/FP pairs** — e.g. V121 (generic type not validated): *"This is the **#1 critical vulnerability** across real Move audits. Attacker creates `Coin<FakeUSDC>`, passes it to a lending protocol that accepts `Coin<T>` … Real-world: Navi Protocol … Econia."*; V122 entry-modifier bypass: *"the `entry` modifier overrides `public(package)` visibility restriction."*
8. **Sui protocol agent checklists** — dense domain knowledge per protocol type, e.g. lending #11 *"PTB flash loan can't be used to manipulate → borrow → repay atomically"*, governance #1 *"Vote weight from past epoch (not current — prevents flash-vote)"*, upgrade #3/#4 (version field + assert on every public function — prefigures move-auditor's SUI-23).
9. **Do-not-report list with a carve-out**: *"Admin-only functions doing admin things (capability-gated operations by design). Standard Move safety (abort on arithmetic overflow). Self-harm-only bugs."* and *"Implausible preconditions (but custom Coin behavior, oracle failure, and shared object contention ARE plausible for protocols accepting arbitrary tokens or using shared objects)."*

### 2.3 Contradictions

- Sui-only: no Aptos coverage (move-auditor covers both) — if both are installed, the router must prefer move-auditor for Aptos.
- V5 (`store` ability "FP: store required for legitimate purposes") vs move-auditor 1.2 ("capability structs should have zero or only `drop`") — posture conflict noted in §1.3.
- Version-gating ritual lives only in the 8-item upgrade checklist here, versus move-auditor's full SUI-23 ritual with grep commands and severity table — this repo is the weaker source for that class.

### 2.4 Gaps

- Older and less maintained than move-auditor (remote VERSION fetch to `sanbir/move-auditor-skills`); no benchmark results published; bundles are context-expensive (8 × full source).
- No tool integration, no regression test machinery, no sample reports shipped.
- Judging gates shared with zk-skills/hydration cl0wdit but unadapted nuances (no Sui abort-semantics gate, no PTB-specific reachability examples).

### 2.5 Classification

**Judge mechanism + specialized sub-skill (Sui).** Its 4-gate judging and bundle orchestration are the unified judge; its protocol checklists are reference material that move-auditor's DeFi files mostly supersede.

---

## 3. `sui-move-skill` — Codex-Oriented Sui Audit with Regression Matrix

### 3.1 Contribution

A production-style Sui-only audit skill (invoked as `$sui-move-auditor`) with the most disciplined **workflow layer** in the cluster: 10-step flow (scope → privilege/asset map → **historical-finding regression matrix** → routed checklists → transition tracing → reachability → candidate validation → FP pass → coverage reconciliation → report). Ships an 8-topic check router (`check-01..08`: access control/caps, object model/shared objects, token/treasury/accounting, storage semantics, external integrations/upgrades, time/oracle/market, PTB composition, observability) with mandatory pairings and explicit skip rules, plus evidence-threshold-per-severity validation.

### 3.2 Most valuable techniques

1. **Historical regression matrix as a blocking deliverable**: *"If any prior audit artifact exists … treat it as mandatory input. Do not begin fresh bug hunting until those prior findings have been converted into a regression checklist with explicit current-code anchors"* — and *"Treat the historical regression checklist as a blocking deliverable … every prior finding has an explicit `Fixed`, `Still Valid`, `Changed Form`, or `Unknown` outcome with code-backed justification."*
2. **Privilege & asset map before hunting** (workflow §2): record user-asset objects, admin/mint authority objects, capability lifecycle, shared vs owned state, and invariants for supply/custody/pricing/access/lifecycle; *"For every security-relevant invariant, list all reachable write paths … Do not stop after tracing the obvious deposit or withdraw function; include alternate funding paths, settlement helpers, maintenance flows, and lifecycle hooks."*
3. **Check router with mandatory pairings** (`check-router.md`): e.g. *"If `check-01` applies and privileged authority touches shared or custody-bearing objects, also load `check-02`"*; and routing rules like `check-03` for "mint, burn, withdraw, deposit, claim, rewards, fees, replay risk, accounting and supply invariants."
4. **Sibling-function diff tactic**: *"compare functions that do the same class of operation (`collect_*`, `add_*`, `withdraw_*`, `*_fix_*`) for a guard, argument, assertion, or event present in one and missing in the other."*
5. **Fixed-accumulator precision vs base-unit denominator (check-03.19)** — the sharpest Move-math check in the repo: *"`acc += scaled_numerator / denominator` where the `denominator` … is denominated in raw token base units … For high-decimal tokens the denominator can exceed the per-interval numerator, truncating the increment to `0` … Do not dismiss truncation as 'dust' until the realistic magnitude is computed"* (precision factor must exceed `denominator/numerator`, commonly 1e18 + u256 intermediate).
6. **Reasoning about absent/unreadable dependencies (check-05.8/5.9)**: *"When a dependency package is absent … do not stop at a caveat … For every external `burn`/`destroy`/`close`/`settle`/`swap`, state the conventional post-condition … and verify the caller satisfies it"* — wrong-source arguments (`amount_max = coin::value(&zero_coin)`) are provable from the caller alone.
7. **Caller-supplied price/anchor not bound to canonical source (check-06.6)**: *"Do not auto-dismiss this as 'trusted admin input' when a canonical on-chain source is available in the same call."*
8. **Pause walked from the recovery side (check-07.8)**: *"a pause flips a global gate … but an emergency withdraw … also runs that same gate, so the recovery path aborts exactly while the protocol is paused"* — recovery paths need a dedicated is-paused assertion.

9. **Replayable signed-workflow binding (check-07.7)**: signature must bind *"the exact object or ticket being consumed, the economic amount or effect being authorized, and a nonce or spent marker … unique for that authorization instance."*
10. **Non-atomic multi-page denominator updates (check-07.9)**: paginated admin updates that set a global denominator before refreshing member weights create a mixed-denominator settlement window.
11. **Evidence threshold by severity** (`candidate-validation.md`): High/Critical need full exploit path; Medium needs *"a concrete reachable path and a code-backed downside such as stale or replayable authorization … A full theft path is not required"*; Low/Info need a concrete path + security-relevant downside; *"do not reject a candidate solely because its severity is below High."*
12. **FP challenge questions** — the best one-line list for Move: *"Does a by-value object parameter already prove legitimate custody? … Is the required capability only issued in initialization, missing `store`, missing transfer paths, or otherwise unobtainable? … Does the proposed PTB composition fail because the one-time resource is consumed…?"*
13. **Coverage reconciliation pass** (workflow §9): 17 explicit questions before finalizing, e.g. *"Did every security-relevant field such as balance, index, status, or timestamp get checked across all alternate write paths for invariant consistency?"*
14. **Report discipline**: fixed 7-section structure including `## Historical Regression Matrix` and `## Rejected or Unvalidated Issues`; severity table keeps Medium/Low/Informational validated by default ("*materially help the reader understand risk, hardening gaps, or incident-response blind spots*").

### 3.3 Contradictions

- Severity philosophy vs move-auditor: this skill is explicitly *retentive* of Low/Info and refuses to discard admin-adjacent findings without code evidence; move-auditor caps weak-confidence findings at Medium and rejects "admin-only" framings aggressively. Both are defensible; a unified skill needs a single evidence-standard table with the two escape hatches named.
- References `references/validation/false-positive-filters.md` in SKILL.md — **file does not exist in the repo** (broken reference; candidate-validation.md carries the content).
- Single-agent sequential design vs move-auditor-skills' parallel agents — no contradiction, but the unified orchestrator should choose per runtime.

### 3.4 Gaps

- No tooling, no scripts, no sub-agent orchestration, no benchmarks/evals.
- No DeFi domain depth beyond check-03 (no liquidation/oracle/staking-specific files comparable to move-auditor's defi/).
- Aptos/Solana out of scope; Sui runtime hard limits (SUI-45/46) absent.

### 3.5 Classification

**Specialized sub-skill (Sui) + validation mechanism.** Its regression matrix, router pairings, and evidence thresholds are the best-in-class validation layer and should be lifted into the unified workflow's pre-audit and validation phases.

---

## 4. `SUIZERO` — Bytecode-Level Static Analyzer for Sui Move

### 4.1 Contribution

A Rust static-analysis engine (v1.0.1) that scans **compiled Move bytecode** (`sui move build` → `.mv` files in `build/<pkg>/bytecode_modules/`) using `move-binary-format` module access, a taint analyzer (`src/core/taint.rs` tracks taint from instruction args through locals/stack/unpack), and 330+ claimed detectors across 15+ classes. Outputs console/markdown/JSON/HTML; supports `--min-severity`, `--fail-on-critical` (CI gate), `--verbose`. Detector families: `SUI-REEN-*` (reentrancy), `SUI-ARITH-*`, `SUI-AC-*` (incl. **Phantom Authorization** SUI-033 and **Capability Theater** SUI-027), `RND-*`, `SM-*`, `MEV-*`, `UPG-*`, `FIN-*`, `FLASH-*`, `GAS-*`, `STORAGE-*`, `VAL-*`, `EVENT-*`, plus extended detectors (`capability_theater.rs`, `phantom_auth.rs`, `receipt_forgery.rs`, `hot_potato.rs`, `vault_binding.rs`, `value_duplication.rs`, `value_conservation.rs`, `nonce_enforcement.rs`, `randomness_oracle.rs`, `ai_agents/mod.rs`, …).

### 4.2 Most valuable techniques / detector concepts

1. **Phantom Authorization** (SUI-033 / SUI-AC-001): *"Function `set_share_price` has a capability parameter `AdminCap` that is NEVER USED in the function body"* — flags capabilities accepted for show, a bug class no LLM skill names as crisply.
2. **Capability Theater** (SUI-027): *"The capability struct `AdminCap` exists but is never used for authentication in any sensitive function"* — the whole capability model is decorative.
3. **Unbound capability** (SUI-031): cap has no binding fields (should contain the ID of the object it protects).
4. **Taint analysis as a first-class stage** (DOCUMENTATION "Phase 3: Taint Analysis"): instruction-level propagation from call args into sensitive sinks — reusable architecture for any VM bytecode.
5. **Bytecode-level analysis** catches what source-only LLM passes miss: struct defs, function bodies, and visibility are decoded from `.mv`, including unpublished modules; works without source.
6. **AI-agent detectors** (`ai_agents/mod.rs`): module-name + struct/function vocabulary matching (`neural`, `layer`, `tensor`, `weight`, `model`, `agent`, `infer`, `predict`, `train`) gates AI-001 "Unbounded AI Action" — a novel detector class for AI-integrated contracts.
7. **CI integration**: `analyze ./build --fail-on-critical` in GitHub Actions; JSON for pipelines.
8. **Detection vocabulary worth stealing**: `ReceiptForgery`, `HotPotato`, `VaultBinding`, `ValueDuplication`, `ValueConservation`, `EmergencyAuth`, `EventStateSync`, `ImproperValidation`, `Temporal`, `Upgradeability`, `Storage`, `StateMachine` — a useful detector-name taxonomy for any Move scanner.

### 4.3 Contradictions

- **Reentrancy detectors (SUI-REEN-001..004) contradict move-auditor's FP doctrine** ("Move has no reentrancy"); SUI-REEN-002 "Shared Object Reentrancy" is real (PTB state-inconsistency) but "Transfer-Based Reentrancy" and "Capability-Based Reentrancy" are EVM-mental-model imports that will mostly FP on Move.
- **EVM concepts leak into the detector set**: `UPG-003 Storage Layout Collisions`, `UPG-004 Constructor Bypass` are delegatecall/init-semantics concepts with no direct Move analog (Move upgrades are bytecode-module replacement; layout changes are compile-checked by the VM).
- Claims "85% accuracy" (README badge) and a `docs/VALIDATION_REPORT.md` — **the validation report is not present in the repo**; the claim is unverifiable.
- Detector count claim (330+) exceeds what DOCUMENTATION.md enumerates (~12 IDs + extended modules); the gap is unexplained.

### 4.4 Gaps

- Bytecode-only: no source-level type generics, doc comments, or `assert!` message semantics; no cross-module value-flow beyond local taint; no proof-of-exploitability (everything is pattern → severity, no reachability gate like the LLM skills' 4-gate judge).
- No FP catalog or known-good patterns (e.g., it would flag capability-holder patterns move-auditor's DESIGN-L files accept).
- No Aptos support; no benchmark dataset shipped; examples only (`vulnerable_project` vaults).

### 4.5 Classification

**Tool integration (Move static scanner)** — wire as the deterministic pre-pass before LLM deep review, but require its findings to pass the unified judge; never trust severities directly.

---

## 5. `safe-solana-builder` (Frank Castle) — Solana Security Skill (build-time)

### 5.1 Contribution

The only Solana security skill in the corpus, and it is a **builder skill, not an auditor**: it generates programs that arrive at audit pre-hardened. `SKILL.md` orchestrates: framework choice (Anchor / native Rust / Pinocchio) → test harness choice (LiteSVM / framework default) → risk tier (🟢/🟡/🔴) → load matching rulesets → produce full scaffold + `lib.rs` + test skeleton + **`security-checklist.md`** documenting every rule applied and every known limitation. References: `shared-base.md` (31 sections, framework-agnostic), `anchor.md`, `native-rust.md`, `pinocchio.md`, `litesvm.md` (CU profiling, sysvar control), plus `examples/nft-whitelist-mint/` (full program + 31-rule checklist). Authored by a researcher with 50+ Solana audits / 250+ Critical-High findings.

### 5.2 Most valuable techniques (verbatim)

1. **Account doctrine** (shared-base §1): *"An account being present in the accounts list does NOT mean it signed"*; *"An attacker can craft an account with identical data layout owned by a malicious program. If you skip the owner check, you'll read and act on spoofed data"*; reinitialization attacks; *"`is_signer` and `is_writable` are per-transaction, not per-instruction."*
2. **PDA doctrine** (§2): canonical bumps only — *"Never allow a user to supply an arbitrary bump seed. An attacker can pre-mine a bump"* — store the bump and re-derive with `create_program_address`; *"Seeds `["AB", "C"]` and `["A", "BC"]` produce the **same PDA**"*; always include the user pubkey in user-state seeds.
3. **Duplicate mutable account attacks** (§4): *"Always add a constraint ensuring two mutable accounts that must be distinct are actually distinct: `constraint = account_a.key() != account_b.key()`"*; *"Ask yourself for every pair of mutable accounts: 'What happens if an attacker passes the same account for both?'"*
4. **CPI safety** (§5): validate program IDs — *"Never CPI into a program ID taken from an account field or instruction data without validating it against an expected constant"*; `reload()` after every CPI (*"Call `reload()` after every CPI before reading any account field"*); sanitize signer pass-through; SOL-balance check around CPI (*"SOL balance checks around CPI"* — slippage for SOL); post-CPI ownership verification; always propagate errors.
5. **Reward accounting** (§21) — the Solana twin of EVM reward-debt bugs: *"Never scale `reward_debt` proportionally when reducing a position without settling first"* (partial-unstake rounding loop); *"Every instruction that pays out rewards must follow the same formula: `pending = total_accrued - reward_debt`, pay `pending`, then set `reward_debt = total_accrued` … Audit every code path … Missing even one is a Critical"*; never retroactively apply a changed rate (per-position snapshots or global accumulator); dead share price; inflation/first-depositor attack (dead shares / min deposit / virtual balances).
6. **Fee-on-transfer delta accounting (Token-2022)** (§21.6): *"Always use balance-delta accounting: `let before = ctx.accounts.vault.amount; … let actual_received = …checked_sub(before)…; // Use actual_received for all state updates — never amount`"*.

7. **Token-2022 extension whitelisting at init** (§23): reject `PermanentDelegate` (*"a complete vault drain vector"*), uncontrolled `FreezeAuthority`, `ConfidentialTransfers`; require TransferHook-aware `remaining_accounts` forwarding; keep an explicit extension allowlist.
8. **BPF stack-frame DoS** (§25): 4096-byte frame limit — *"Anchor instruction contexts with 6+ `InterfaceAccount` or `Account` fields … can exceed this limit, causing runtime access violations (not compile-time errors). This is a complete DoS"*; treat `Stack offset of XXXX exceeded max offset of 4096` build warnings as blockers; `Box<>` large fields.
9. **State-machine integrity** (§26): sentinel timestamps must be valid unix times; every terminal-state path runs the same cleanup; status-transition guards use **allowlists, not denylists**; *"Terminal States Must Be Absorbing (Non-Rewritable)"*; paired time gates share one deadline source.
10. **Slippage & fee ordering** (§27): *"Slippage Guards Must Protect Net Amount, Not Gross"*; fee base must match the actual swapped amount; fee collection must not block the user's payout.
11. **Config management** (§29): frontrunnable initialization without identity check; *"Config Update APIs Must Preserve 'No Change' Semantics"* (partial updates via patch semantics, never silent zeroing); unbounded admin params retroactively breaking live entities (snapshot terms into per-entity state).
12. **Withdraw/drain safety** (§30): withdrawal amount validated against protocol allocation (liabilities settled before residual extraction); *"After full settlement/completion drains, zero all reserve/balance accounting fields."*
13. **Anchor specifics** (`anchor.md`): `init` vs `init_if_needed` (*"Critical Distinction"* — init_if_needed is reinitialization-friendly), `close = recipient` with rent to trusted recipient, `realloc` safety, `has_one` enforcement, `token_interface` for Token-2022.
14. **Native Rust validation sequence** (`native-rust.md` §1.1): owner → signer → discriminator → key checks in fixed order; `try_from_slice`; verify data length before deserializing.
15. **Test hygiene** (`litesvm.md`, SKILL.md): security edge-case matrix scaffolded with `TODO` bodies; CU summary test `zz_cu_summary()`; LiteSVM RPC limitations documented.

### 5.3 Contradictions

- "Never use standard `+`, `-`, `*` on financial values" (§3.1) vs hydration cl0wdit FP-002 (saturating is fine with documented intent on non-balance counters) — resolvable: both require checked math on balances; they differ on counters.
- Its Token-2022 §23 (reject PermanentDelegate/FreezeAuthority) is a *builder default*, whereas `solana-token-extensions-security` treats *some* of those as acceptable when the protocol explicitly trust-lists mints — posture difference between "safe default" and "audit truth".
- No auditor-side verification loop (no judge); findings are design-time rules, not triage mechanics — complementary to, not competing with, an audit skill.

### 5.4 Gaps

- Generation-focused: no exploit-path proof, no severity framework, no dedup/triage.
- Roadmap admits missing: invariant testing (Trident/fuzz), native-Rust example, Token-2022 deep-dive reference, AMM/lending pattern references.
- LiteSVM partial-RPC caveat is documented but unaddressed for wallet flows.

### 5.5 Classification

**Build-time guard + reference material (Solana).** The unified skill should use it in "develop mode"; in "audit mode," §1–§31 convert almost one-to-one into a Solana checklist, and the example's `security-checklist.md` is a template for the deliverable.

---

## 6. `solana-token-extensions-security` — Token-2022 Audit Skill

### 6.1 Contribution

A compact audit pack (SKILL.md + `references/token-2022-patterns.md` 693 lines + `references/finding-templates.md`) for reviewing any Solana program that touches Token-2022 mints/accounts. Adds the **issue bank** pattern: real audit findings mapped to reusable Token-2022 failure modes (fee accounting drift, nominal-vs-spendable mismatch, mint/account binding, permanent-delegate custody breaks, transfer-hook `remaining_accounts` gaps, extension space computed too early, mixed token-program CPI wiring, confidential-proof validation truncation). Reporting format is deliberately exploit-shaped: severity × confidence (0.0–1.0 score) × evidence × **Alice/Bob scenario** × preconditions × exploit path × fix.

### 6.2 Most valuable techniques

1. **The core assumption inventory** (SKILL.md): *"Assume the target may be vulnerable whenever it: trusts mint/account state without verifying extensions; assumes all SPL-like tokens behave like classic SPL Token; assumes transfers are synchronous, full-amount, transferable, unfrozen, or memo-free; trusts mint addresses without considering close-and-reinitialize history; treats token balances as invariant despite permanent delegates, mint authorities, or seizure-style controls."*
2. **Extension catalog as exploit-shape library** (`token-2022-patterns.md`): per extension — what it changes / broken assumptions / exploit shape / impact / minimal fix. Examples: transfer fees (*"Do not treat `calculate_fee` and `calculate_inverse_fee` as strict inverses, and do not assume `withheld_amount` is real-time without harvesting"*); permanent delegate (*"transfer paths may automatically authorize it without requiring the source account owner"*); default-account-state (frozen-by-default bricks vault init); CPI guard (breaks owner-authority CPI flows); transfer hook (*"hook programs that fail to verify supported mints; PDAs shared across different mints"*).
3. **Dual WSOL mints**: SPL `So111…11112` vs Token-2022 `9pan9…XejP` — *"If a protocol special-cases WSOL, make sure it distinguishes these addresses explicitly."*
4. **Close-and-reinitialize history**: *"do not treat current extension state as proof of historical safety"* — a closeable mint can be re-initialized with different extensions; old token accounts remain valid but incompatible.
5. **Confidential-transfer edge cases**: proof validation truncating after the expected prefix and ignoring unused commitments.
6. **Parallel review passes** for large audits: transfer flows/fees/hooks; mint lifecycle/sizing/close-and-reinit; metadata/group/WSOL/program IDs; vault/escrow semantics; CPI wiring spanning both token programs; confidential proofs; manual CPI wrappers needing `remaining_accounts`.
7. **Severity vs confidence split**: *"severity measures impact; confidence measures certainty; confidence score should reflect how much of the exploit path is proven, not how severe the impact is."*
8. **Strong default heuristics**: *"Default to lower severity when: the extension is cosmetic only … the protocol explicitly trust-lists mints and authorities; live balance checks and post-transfer reconciliation already exist."*

### 6.3 Contradictions

- vs safe-solana-builder §23: builder says *reject* PermanentDelegate/FreezeAuthority mints at init; this skill says protocols may accept them if policy is explicit and balances are re-checked before sensitive settlement. Both are right in their context (safe default vs audit judgment).
- No severity taxonomy of its own (High/Medium/Low/Info only) — a unified skill must map its confidence scores onto the cluster's evidence-gate model.

### 6.4 Gaps

- Only 3 of the issue-bank patterns fully encoded in prose; the rest are look-for/fix-direction notes.
- No tooling, no PoC harness, no anchor-specific constraint recipes (unlike safe-solana-builder's `anchor.md`).
- No coverage of classic SPL Token interactions beyond the WSOL note.

### 6.5 Classification

**Specialized sub-skill + reference material (Solana Token-2022).** Best used as the Token-2022 lens inside the unified Solana auditor and as the canonical extension cheat-sheet.

---

## 7. `solskill` (Cyfrin) — Solidity Standards + BattleChain

### 7.1 Contribution

Three Claude skills: `solidity` (production-grade Solidity dev standards: code quality, testing patterns, security practices, Foundry workflows), `battlechain` and `battlechain-tutorial` (Cyfrin's BattleChain — a ZKSync L2 inserting a battle-testing phase between testnet and mainnet: *"Dev → Testnet → BattleChain → Mainnet. Protocols deploy audited contracts with real funds, whitehats legally attack them for bounties under Safe Harbor agreements, and surviving contracts promote to production"*). Includes contract addresses, `battlechain-lib` helpers, Safe Harbor flows, and a caveat that mainnet CreateX is **not** at the well-known `0xba5Ed…` address.

### 7.2 Most valuable techniques

1. The battle-testing-with-real-funds stage is a **validation mechanism** worth knowing: it is an operational alternative to (not replacement for) audit.
2. The `solidity` skill's checklist (philosophy, code quality/style, deployment, governance, CI, Foundry) is a dev-standards baseline — useful as the "develop mode" companion for EVM; nothing non-EVM specific.
3. `disable-model-invocation: true` in battlechain frontmatter — a correct pattern for reference-only skills that should not auto-fire.

### 7.3 Contradictions / 7.4 Gaps

- Not an audit skill; no vulnerability catalog, no judge. EVM-only. Its "audit" value is confined to deployment lifecycle and testing discipline.

### 7.5 Classification

**Tool integration / validation mechanism (EVM ops).** Low priority for the unified non-EVM skill; keep the BattleChain concept as an optional deployment-stage gate.

---

## 8. `zk-skills` / `circom-auditor` — ZK Circuit Audit Skill

### 8.1 Contribution

The strongest ZK-circuit audit skill in the corpus. 206-line `SKILL.md` with runtime selection (Codex delegated → Claude 17-agent → local single-agent), an audit console with a bounded worker pool (max 6 running agents), deterministic `scripts/build_audit_context.py` context builder, and: a **48-vector attack catalog split into six "slice" files** (signal-field, range, selector-accumulator, binding-1, binding-2, regex-language), each vector in **D/FP/Source** format grounded in a real audit finding (zkbugs dataset / published reports); 13 hacking agents; a `senior-auditor-sop.md` defining three mandatory "mental tools"; a 4-gate `judging.md` tuned to the R1CS threat model; a delegated workflow with a separate **triage-agent turn**; and eval benchmarks (circomlib-decoder, selfxyz-packbytes, wormprivacy-spend).

### 8.2 Most valuable techniques (verbatim)

1. **Cross-cutting mantras** (`attack-vectors.md`) — the ZK equivalent of a FP catalog, one line each:
   - *"Every `<--` is a constraint hole until proven otherwise."*
   - *"Every `LessThan(N)` operand must come from a `Num2Bits(M ≤ N)` chain."*
   - *"Every `Num2Bits(254)` over BN254 needs `_strict` or an alias check."*
   - *"Every divisor in `<-- a/b` needs `IsZero(b).out === 0` upstream."*
   - *"Every `Mux*` selector needs `s * (s - 1) === 0` upstream."*
   - *"Every public input must appear in at least one `===` / `<==` constraint."*
   - *"`assert(...)` is not a constraint — it's a compile-time check the verifier never sees."*
2. **The declarative doctrine** (`senior-auditor-sop.md`): *"Circom is **declarative**, not imperative. There is no execution order to exploit — there is only the set of constraints and the space of witnesses that satisfy them. So the senior auditor's question is never 'what does this line do?' It is always 'what does the constraint system still ALLOW?'"*
3. **Mental tool protocol with grep-verifiable markers** (`shared-rules.md`): `[Feynman: <Template>]` on opening a template (explain what it proves in plain English; *"Wherever your plain-English explanation gets fuzzy … that is an unconstrained signal, and that is where bugs hide"*); `[Socratic: file:line]` on unclear constraints; `[Inversion: <Template>]` with concrete malicious-prover values (*"Specific values like `in = p - 1`, not abstractions"*). The orchestrator greps markers after the run; *"Skipped markers downgrade the value of your findings and are recorded as workflow violations."*
4. **Threat model = soundness/completeness/privacy** (`judging.md`): a soundness break needs "a malicious prover can craft a witness/inputs that satisfy the R1CS but violate the protocol's intended semantics, AND a verifier accepts the resulting proof"; completeness = honest prover bricked; privacy = verifier learns a function of private inputs.
5. **Gate 1 refutation discipline**: *"a finding fails ONLY when a specific constraint on the witness path provably pins the value the attacker needs free … 'the witness generator only emits canonical values' → clears. Witness generators do not constrain the prover; only the R1CS does."*
6. **Gate 3 trusted-party demotion**: setup/designated-prover harms are demoted *"unless an unprivileged amplifier is named"* (toxic-waste leak, designated-prover gap via public entry, setup-assumed invariant that any prover can violate).

7. **Code-shape-organized vectors** (grep-first, not class-first) — the catalog is *"organized by **code shape** (the kind of Circom construct you grep for), not by abstract bug class"*. Star vectors: V-D1 selector-as-enabler (*"the disabled branch trivially satisfies the check at zero … The author intended graceful disablement; the actual semantics are silent bypass"*, panther nullifier-verification-can-be-disabled); V-B3 Num2Bits(254) aliasing (two decompositions, `x` and `x+p`); V-A3 witness-only division collapse (`0 === 0` when divisor is zero — recurs across every EC primitive computing a slope); V-H4 public input never constrained (*"the linear 'dummy use' is optimised away by `circom -O2`"*); V-E2 wrong-side keying; V-L1 *"`/` is field-inverse, `\` is integer division"*; V-L5 field comparison normalized to `(-p/2, p/2]`.
8. **Signature/merkle precondition doctrine** (binding-2 mantra): *"A signature/merkle gadget enforces only what its body constrains — every precondition (on-curve, in-subgroup, `< order`, fixed depth, domain tag) is the caller's job until proven otherwise."*
9. **Weaponization / propagation rules** (shared-rules): *"If you find that `circomlib.MontgomeryAdd` is unsound when `in[0] == in[1]`, then every template that calls `MontgomeryAdd` (directly or transitively …) inherits the bug. Trace the include graph and report every consumer."*
10. **Dedup with detector-provenance preservation** (orchestration): group by `TemplateName | signal_or_local | bug-class`; never merge across templates or signals; *"Preserve and union detector sets … the final report item must say `Detected by: agent-2, agent-8, agent-14`"*; second pass at `(Template, signal)` ignoring bug_class; print `Completeness: N unique … covered`.
11. **Separate triage turn** (Turn 5): fresh agents get only the drafted finding and verdict `Exploitable`/`Not Exploitable`; *"If the triage response is genuinely ambiguous, default to `Exploitable` and note the uncertainty"*; *"Keep findings the triager marks `Not Exploitable`; the disagreement is useful to the user."*
12. **Safe patterns list** (`judging.md`): `Num2Bits_strict`, `<==` for quadratic relations, canonical inverse + `IsZero(x).out === 0`, `s*(s-1)===0` before mux, `BigLessThan(...).out === 1` after BigMod, `IsEqual(a,b).out === 0` before AddUnequal-style EC, Poseidon intentHash binding.
13. **Local-mode grep list** (SKILL.md step 6): the 10 concrete witness-manipulation shapes to search first (unpaired `<--`, `assert` for runtime constraints, missing strict/comparator bounds, divisor checks, selector booleanity, unbound public inputs, field wraparound, peripheral preconditions).
14. **Docs discipline**: *"Read project docs … use them only to understand intended semantics, never to excuse missing constraints."*

### 8.3 Contradictions

- vs EVM judge gates: Gate 3 replaces "unprivileged actor" with "unprivileged prover," and adds the trusted-setup demotion ladder — an EVM judge cannot be reused verbatim; the unified judge needs a per-domain threat-model stanza.
- vs move-auditor confidence systems: zk-skills uses numeric 100-minus-deductions (like move-auditor-skills) while move-auditor uses signal-strength gating; both cap severity by confidence, but the unified skill must pick one representation (numeric score + cap table).
- "Compile-time `assert(...)` used in its legitimate role" is a safe pattern in judging.md, while the mantras call every `assert` suspicious — internally consistent (context-dependent) but easy to misapply; keep the V-D5 pairing rule (mirror every assert with a real constraint gadget) as the tiebreaker.

### 8.4 Gaps

- Circom-only: no Halo2/Noir/AirScript coverage despite the category being "ZK."
- No symbolic/tool integration (no Picus/ECNE/circomspect wiring), despite mentioning "Picus-style determinism checks" as an FP guard.
- Marker-grep enforcement depends on subagent runtimes exposing working text; local mode is a softer discipline.
- Benchmarks are 3 projects; no published pass-rate.

### 8.5 Classification

**Core methodology (ZK/circom) + judge mechanism.** The Feynman/Socratic/Inversion protocol is the best generic "reasoning discipline" artifact in the entire corpus and should be generalized to Move/Solana audit lenses as well.

---

## 9. `weasel` — Solidity Static Analyzer with MCP + AI Skills

### 9.1 Contribution

"Solidity static analyzer you can talk to": a Rust-based parallel analyzer wrapped in (a) a Claude Code plugin of 9 skills (`weasel-analyzer`, `-poc`, `-validate`, `-report`, `-filter`, `-gas`, `-explainer`, `-simplify`, `-overview`) and (b) an MCP server (`weasel_analyze`, `weasel_finding_details`, `weasel_detectors`) for any MCP-compatible IDE. CLI: `weasel run -s ./contracts -e ./test -m High -o report.md` (markdown/JSON/SARIF for GitHub Code Scanning). Detectors graded High/Medium/Low/Gas/NC (reentrancy, unchecked calls, delegatecall, missing access control, oracle manipulation, pragma, zero-address…).

### 9.2 Most valuable techniques

1. **Three-mode dispatch** (`weasel-analyzer/SKILL.md`): Quick (tool only, ~500–2000 tokens), Review (read-only manual reasoning), Full Audit (combined) — with explicit context-cost annotation per mode, the best lightweight triage pattern for tool+LLM pairing.
2. **Full-audit pipeline**: Step 0 context gathering (*"Read README.md … Check for known-issues.md or audit/ folder … This prevents reporting known issues or intended behavior as bugs"*) → scan → triage ALL High/Medium, mention-only Low/Gas → deep dive each High/Med (`weasel_finding_details` + read source + "Document: Confirmed / False Positive") → **manual review for what static analysis cannot detect** (*"Business logic issues; Economic vulnerabilities (flash loans, sandwich, oracle manipulation)"*).
3. **PoC skill rules**: *"NEVER mock or simulate the vulnerable contract … ALWAYS use the actual contract with real deployment"*; *"Assertions prove the vulnerability, not console output"* — zero celebration/banner logs; pre-commit checklist; rationalizations-to-reject table ("Console output helps explain the attack" → *"That's what the report is for. PoC proves, report explains."*).
4. **Validate skill with 5 verdicts**: CONFIRMED / PARTIAL / NOT EXPLOITABLE / **KNOWN ISSUE** / **BY DESIGN** — the last two explicitly consume README/known-issues/`// @audit-known` comments before code reading; *"The code looks vulnerable, must be exploitable"* is a rejected rationalization (*"Code appearance ≠ exploitability. Trace the FULL attack path"*).
5. **SARIF + `weasel mcp add --target cursor|windsurf|codex|gemini`** — clean multi-IDE distribution mechanics worth copying for any analyzer.

### 9.3 Contradictions

- EVM-only; detector semantics Slither-like; the "review mode" explicitly disables the tool — opposite of SUIZERO/GPTScan which treat the tool as the primary signal.
- Report/severity conventions are the tool's own (High/Medium/Low/Gas/NC) — needs mapping onto the unified severity×confidence model.

### 9.4 Gaps

- No non-EVM detectors; no economic/business-logic detectors; skill set is Claude-only (MCP covers other IDEs but without skills).
- No benchmark data or FP-rate published; detector source is minimal in-repo (`src/detectors/{high,medium,low,gas,nc}`).

### 9.5 Classification

**Tool integration (EVM static analyzer + PoC/report skills).** The weasel-poc/validate/report skill trio is the best *post-finding* workflow in the cluster and should be generalized (PoC rules and validate verdicts transfer unchanged to non-EVM audits).

---

## 10. `GPTScan` (MetaTrustLabs, ICSE'24) — GPT + Program Analysis for Logic Vulns

### 10.1 Contribution

Academic hybrid (paper: *"GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis"*, ICSE 2024): a static pre-filter (Falcon + ANTLR/Solidity callgraph) selects candidate code segments per rule, GPT summarizes rule *properties* into a "KeySentence," then a second GPT pass matches candidates against the sentence; a **whitelist preprocess** filters known-safe patterns (modifiers, checks) to cut false positives. Ships 10 rule YAMLs: FrontRun, Flashloan_Price, Flashloan_Buy, Flashloan_Vote, FirstDeposit, Slippage, ApprovalNotClear, UnauthorizedTransfer, WrongOrder_Checkpoint, WrongOrder_Interest.

### 10.2 Most valuable techniques

1. **Rule DSL** (`src/rules/FrontRun.yml`): declarative vulnerability = `property` (natural language) + `functions` (names) + `function_public` + `function_parameters` (`address`) + `function_not_inside` (mitigation regexes like `transferFrom(msg.sender`, `REGEX: (if|require)\s*\(.*msg\.sender`) + `check_only_modifier` + `activate` + `output` (MWE title/description/recommendation) + a `static` sub-rule (`call_arg_check` for `safeTransferFrom`/`msg.sender`). This is the cleanest **vuln-as-data** schema in the corpus — worth adopting as the unified rule format.
2. **Two-stage GPT prompting** (`query_template.py`): stage 1 distills impact sentences into a function-name-free "KeySentence"; stage 2 matches code segments against it — reduces hallucination by separating summarization from matching.
3. **Static checks as text predicates** (`static_check.py`): order checks (`__order_first_b`), comparison checks (`__has_check`), call-arg checks — encoding "state A must be updated before state B" (WrongOrder_Interest/Checkpoint rules) as positional logic on text.
4. **Whitelist filtering** (`whitelist.json`, `modifier_whitelist.json`): known-mitigation snippets prevent re-reporting guarded code.
5. **Documented limitation as a lesson**: *"make sure that your path do not contain keywords like `external`, `openzeppelin`, `uniswap` … since we are using a naive way to match the path"* — a cautionary tale about fragile path heuristics in audit tooling.

### 10.3 Contradictions

- Solidity-only; targets *logic* vulnerabilities (not the taint-style classes SUIZERO/weasel cover); requires solc-select + Java + API key; framework support (Hardhat/Truffle/Brownie) is dated.
- vs LLM-skill orthodoxy: GPTScan trusts a static filter to choose candidates, then LLM to confirm — the inverse of the "LLM proposes, judge disposes" pattern in the audit skills; both orderings are useful and should coexist in the unified pipeline.

### 10.4 Gaps

- 10 rules, no Move/Solana/ZK analogs; empty-output failure mode is silent (no error when path matching fails); no maintained benchmarks beyond the paper's Web3Bugs/DefiHacks/Top200.

### 10.5 Classification

**Tool integration (EVM hybrid scanner).** Preserve two artifacts: the rule-YAML DSL and the two-stage prompt design; port the WrongOrder/FirstDeposit/Flashloan rule family to Move/Solana checklists.

---

## 11. `hydration-node` — Substrate cl0wdit Audit Skill + Incident Playbook

### 11.1 Contribution

The Hydration (HydraDX) node repo ships two AI skills: **`hydration_cl0wdit`** — a parallelized Substrate/Rust runtime audit (same v2 lineage as move-auditor-skills/zk-skills) with 11 agents (incl. a test-benchmark agent that gets test/mock/bench files + a dispatchable summary), `--pr` mode auditing a GitHub PR via the API, a **known-false-positives catalog**, 4-gate judging, and 25+ Substrate attack-vector classes plus a protocol-specific distillation of 11 audit reports/bounties (2022–2025); and **`circuit-breaker-incident`** — a 297-line incident-response playbook with query scripts for reconstructing a circuit-breaker lockdown event, calculating user losses, and lifting lockdown.

### 11.2 Most valuable techniques

1. **Known-false-positive catalog** (`known-false-positives.md`, FP-001..FP-010+) — the best Substrate/Rust-specific anti-FP reference: *"Since FRAME v2 (~Substrate 0.9.25+), all `#[pallet::call]` dispatchables are automatically wrapped in a transactional layer … Only flag missing transactional semantics for **non-dispatchable** internal functions"*; FP-002 saturating math is fine *"when clamping is the desired outcome … Only flag `saturating_*` when: (a) the operation is on a balance or share calculation … AND (b) there is no preceding guard"*; FP-003 `.unwrap_or_default()` never panics; FP-006 `SafeCallFilter = Everything` only matters for untrusted XCM origins; FP-007 governance changes are bugs only when *"the change retroactively harms locked/committed users … corrupts existing state … or missing sanity bound (e.g., fee settable to >100%)"*; FP-008 division-before-multiply is fine inside fixed-point libraries; FP-009 storage deposits only needed for unbounded/high-limit storage with no deposit/fee/ED gate.
2. **PR-scoped audit mode** (`--pr`): fetch changed `.rs` via GitHub API, split production vs test files, audit only the diff surface — a clean pattern for continuous-audit use.
3. **Test-benchmark agent**: receives test/mock/bench code + a summary of every `#[pallet::call]` function — hunts *"tests that assert the wrong thing, benchmarks that under-weight, mocks that hide production behavior"* (the only repo doing this).
4. **Substrate attack-vector catalog**: unsafe arithmetic (release-mode silent wrapping!), saturating masking, divide-before-multiply, `^` XOR-vs-pow, unsafe `as` casts (→ `unique_saturated_into`/`TryInto`), panicking ops in runtime code (brick block production), `RandomnessCollectiveFlip` weakness, storage exhaustion, unbounded decoding (`decode_with_depth_limit`).
5. **Protocol distillation with mechanism summaries** (`hydration-attack-vectors.md`) — every entry: Source (C4 H-01 etc.) / Impact / Mechanism / Pattern. E.g. *"Stableswap buy() with asset_in == asset_out (Critical) … Drains entire pool liquidity for 1 wei cost … Missing input validation on trade pair identity"*; *"Cross-Pool LP Share Theft via Missing AssetPair Validation (Critical) … Pattern: Confused deputy — user-controlled parameter (`AssetPair`) derives a security-critical identifier (`amm_pool_id`) without cross-validation against the stored authoritative value"*; *"EMA of reciprocal price diverges — `EMA(1/price) != 1/EMA(price)`"*; *"Complete liquidity removal permanently disables pool … If someone sends 1 token directly, new LPs get 0 shares (permanent fund lock)."*
6. **Incident playbook** (`circuit-breaker-incident`): Step 1 find lockdown event → Step 2 all events in trigger block → Step 3 asset details → Step 4 calculate amounts → Step 5 XCM message link → Step 6 report template; plus known gotchas, chain-direct fallback scanning, and past-incident reference data. This is the only **incident-response skill** in the corpus.

### 11.3 Contradictions

- FP-002 directly resolves the safe-solana-builder §3.1 tension (checked math on balances; saturating only with intent).
- Judging.md is the v2 4-gate judge verbatim-adapted; same strength, same missing chain-specific stanzas (no weight/benchmark gate, no XCM-origin reachability ladder — partially covered by FP-006/FP-007 instead).
- Hydration vectors say "Arbitrage bot operates on outdated values (Low)" — a finding class the EVM skills would treat as design smell; consistent with the repo's own conservative severity.

### 11.4 Gaps

- Substrate-only; deeply protocol-specific (Omnipool/Stableswap/XYK); no Aptos/ICP/Polkadot-generic coverage; skills live inside the node repo, not standalone.
- No benchmark/evals; no tool integration (scout-audit referenced but not wired).

### 11.5 Classification

**Core methodology (Substrate/Rust runtime) + judge mechanism + reference material.** FP-001..010 and the attack-vector format are the template for any non-EVM runtime's FP catalog; the incident playbook is a new skill class to preserve.

---

## 12. `openzeppelin-skills` — Library-First Secure Development + Sui Review

### 12.1 Contribution

OpenZeppelin's official skill set: `develop-secure-contracts` (pattern discovery from library source across Solidity/Cairo/Stylus/Stellar/Sui Move), `review-sui-contracts` (AI review of Sui integrations against OZ Contracts for Sui), `setup-*` and `upgrade-*` skills per language, plus `dev/PRINCIPLES.md` and a 647-line `dev/TESTING.md`. Deliberately **not an audit skill**: *"This is an AI code review, not a formal security audit. It supports the audit process by flagging misuse and deviations early."*

### 12.2 Most valuable techniques

1. **Library-first doctrine** (`develop-secure-contracts`): *"Prefer Library Components Over Custom Code — 1. Exact match exists? Import and use it directly … 3. No match exists? Only then write custom logic."* and *"NEVER copy or embed library source code into the user's contract. Always import from the dependency so the project receives security updates."*
2. **Pinned-revision truth** (`review-sui-contracts`): *"Read the primitive's API and behavior at the revision the integrator builds against — resolve each OZ dependency's pinned rev from `Move.lock` and use that source / those doc-comments, not `main`."*
3. **Type-argument authority check**: *"For each OZ primitive parameterized by a witness or generic/phantom type, check who supplies it and whether it is the correct authority. A caller-chosen type is an authority the caller controls, so the trusted party must fix it, not the caller. And a developer-fixed type must be the right one for the action — a privileged operation gated by a lower-privilege role's `Auth` … is a privilege-escalation bug."* — the crispest statement of the Move witness/generic-authority rule anywhere.
4. **Deviation-based review**: compare the flow against the closest `examples/` recipe or doc-comment idiomatic-usage block; flag *"an object shared vs. embedded against its intended ownership model, a required setup step skipped, a returned value or receipt ignored."*
5. **Verify-before-reporting triad**: *"try to disprove each finding: quote the exact line … confirm it is a genuine deviation and not an intentional, documented choice; and confirm you can state a concrete one-line fix. Drop whatever does not survive all three, and keep the severity bar high — a short review a developer trusts beats a long one they skim."*
6. **Copied-source flag**: *"Flag any OZ module source copied into the project instead of imported via MVR — copies miss security updates."*
7. **Conventions as findings**: styleguide violations reported as findings, lint warnings fixed not suppressed; test coverage of abort/branch paths (role-denied, expired, over-limit) not just happy path.

### 12.3 Contradictions

- Boundary vs move-auditor: OZ explicitly refuses to be an auditor; a unified skill must keep the "integration review" and "security audit" layers separate (mirrors weasel Review vs Full Audit modes).
- No severity taxonomy of its own; ordering by severity with one-clause findings assumes the reviewer's judgment.

### 12.4 Gaps

- Only Sui among non-EVM Move chains; no Solana/Rust review skill; no judge/verification machinery; depends on network access for STYLEGUIDE/llms.txt fetches (with retry guidance).

### 12.5 Classification

**Build-time guard + specialized sub-skill (Sui integrations).** The type-authority check and pinned-revision rule should be folded into the unified Move checklist; PRINCIPLES/TESTING are reference material for the "develop mode."

---

## 13. Cross-Repo Synthesis: What Transfers from EVM, What Is Chain-Specific

### 13.1 Fully transferable (chain-agnostic bug classes — reuse EVM knowledge verbatim)

| Class | EVM source of truth | Non-EVM counterparts found in this cluster |
|---|---|---|
| Reward-debt / accumulator settlement | ERC4626/Compound rewardDebt | move-auditor DEFI-88, DEFI-13/15/16, 12.1; sui-move-skill check-03.7/03.19; safe-solana-builder §21.1–21.2 (settle before shrinking; same formula on every payout path) |
| First-depositor inflation | OZ/4626 virtual shares | move-auditor DEFI-11; safe-solana-builder §21.5 (dead shares / min deposit / virtual balances); move-auditor-skills vault checklist #1 |
| Fee-on-transfer delta | ERC777/FoT tokens | safe-solana-builder §21.6 balance-delta accounting; token-extensions "Transfer-Fee Accounting Drift" (calculate_fee ≠ strict inverse, withheld fees) |
| Oracle manipulation / staleness | Chainlink/TWAP checks | move-auditor DEFI-17..24, DEFI-95; hydration "EMA(1/price) ≠ 1/EMA(price)"; sui-move-skill check-06.2/06.5/06.6 |
| Slippage / min-amount-out | Uniswap minOut | move-auditor DEFI-43..49 (incl. PTB sandwich DEFI-49); safe-solana-builder §27 (net-not-gross!); hydration "remove_liquidity no min_shares_out" |
| Liquidation economics | Compound/Aave liquidations | move-auditor DEFI-50..66, DEFI-81/83/91/92/94 + DESIGN-L1..L4; safe-solana-builder (bonus, dust, close-factor); hydration liquidation vectors |
| Signature replay / policy snapshot | EIP-712 / ERC1271 | move-auditor DEFI-74..79 + DEFI-89 (signing-time policy); sui-move-skill check-01.6/07.7; zk-skills V-H1/H6/H14 (binding/replay across the proof boundary) |
| Check-vs-settlement divergence | EVM "check vs execution" bugs | move-auditor DEFI-91/92 four-axis table — **export this table to every chain** |
| Config-update retroactivity | EVM admin setter bugs | move-auditor 12.2 + DEFI-80/84; safe-solana-builder §29/§31.1; sui-move-skill check-07.5; hydration FP-007 |
| State-machine / terminal-state integrity | EVM state machine audits | safe-solana-builder §26 (allowlist transitions, absorbing terminals, one deadline source); sui-move-skill check-07.3 |
| Unbounded growth / DoS | EVM unbounded loops/arrays | move-auditor SUI-15/30/45 (incl. object-size cap); sui-move-skill check-02.5; hydration storage exhaustion; safe-solana-builder §25 (stack frame) |

### 13.2 Chain-specific (do NOT transfer EVM assumptions; load the chain file)

**Move/Sui:**
- **Capability/witness discipline** — access control is object-shaped: signer checks are weak, capabilities must be non-`copy`/non-`store`, OTW one-time; SUIZERO's "Phantom Authorization"/"Capability Theater" detectors + OZ's type-authority rule cover the failure modes.
- **Abort ≠ revert semantics** — overflow aborts (DoS, not corruption); the killer consequence is abort-**before-checkpoint** permanent deadlock (12.1/DEFI-86) — an EVM auditor will miss this every time.
- **PTB atomic composition** — per-call limits are bypassable by same-transaction re-calls (SUI-28, DEFI-83); `public fun` is PTB-composable on Sui but not an entry on Aptos; PTB is also the flash-loan/sandwich primitive (SUI-02, DEFI-49).
- **Upgrade model** — every historical package version stays executable (SUI-23); immutable protocol + upgradeable dependency = brick (SUI-22); `UpgradeCap` policy tiers (SUI-27); version gates + migration ritual mandatory.
- **Object lifecycle** — dynamic fields must be cleaned before delete (SUI-25), hot potato receipts must bind snapshots (SUI-17/20), shared objects are consensus-contended (SUI-31), denylist is validator-level with an epoch gap (SUI-21).
- **Freeze/pause semantics** — Sui has no "freeze" primitive beyond immutable objects/packages; pause must be walked from the recovery side (sui-move-skill check-07.8); asymmetric pause is a distinct Move finding class (DEFI-28).

**Solana/Anchor:**
- **Account validation** — signer ≠ presence, owner check, discriminator (type cosplay), reinit, duplicate-mutable-account attacks, `is_signer/is_writable` are per-transaction (safe-solana-builder §1, §4).
- **PDA doctrine** — canonical bump, seed collision `["AB","C"]` vs `["A","BC"]`, purpose isolation, user pubkey in seeds (§2).
- **CPI hygiene** — program-ID pinning, `reload()` after CPI, signer pass-through sanitization, SOL balance checks, rent/lamport invariant (§3.4, §5, §6).
- **Token-2022** — extension whitelisting, transfer-fee delta, transfer hooks + `remaining_accounts`, close-and-reinitialize, dual WSOL, permanent delegate, confidential transfer edge cases (token-extensions skill + §23).
- **BPF/runtime limits** — 4096-byte stack frame DoS, compute-unit budgets, account size (`ExtensionType::try_calculate_account_len` after all extensions).

**ZK circuits:**
- Threat model is **soundness/completeness/privacy**, attacker is the *prover*; `assert` is not a constraint; `<--` is a constraint hole until proven; every gadget precondition (on-curve, `< order`, range, domain tag) is the caller's job (zk-skills mantras + judging).
- The declarative reading discipline (Feynman/Socratic/Inversion) is the required reasoning mode — imperative EVM tracing does not transfer.

**Substrate/FRAME:**
- Dispatchables are auto-transactional; saturating math may be intended; `.unwrap_or_default` is safe; storage deposits gate unbounded writes; weights/benchmarks are security-relevant; XCM origin filters define trust (hydration cl0wdit FP-001..010 + substrate vectors).

### 13.3 Cross-cutting architecture patterns worth unifying

1. **Judge lineage (v2 family):** 4 gates + numeric confidence + single-pass protocol — identical in move-auditor-skills, zk-skills, hydration cl0wdit. Make it the default judge; add per-chain Gate-3 stanzas (PTB composition for Sui; malicious prover for ZK; unprivileged origin for Substrate).
2. **Anti-FP engineering:** three complementary mechanisms should be stacked — (a) rationalizations-to-reject + known-FP catalogs (move-auditor FP catalog, hydration FP-001.., zk "safe patterns"), (b) evidence-source tagging with mock rejection (move-auditor), (c) confidence caps on severity (all).
3. **Vuln-as-data:** GPTScan's rule YAML is the best machine-readable format; move-auditor's signal router is the best *routing* format. A unified rule file should combine both (signals → files → per-rule property/mitigations/severity).
4. **Regression-first workflow:** sui-move-skill's blocking regression matrix is the single most under-adopted idea in the corpus — make it a mandatory phase.
5. **Verifier/triage separation:** zk-skills' separate triage turn + weasel's validate verdicts + move-auditor's devil's advocate = three independent implementations of "disprove before report"; keep all three as optional passes.

### 13.4 Contradiction register (must be resolved in the unified skill)

| # | Tension | Repos | Resolution |
|---|---|---|---|
| 1 | "No reentrancy in Move" vs reentrancy detectors | move-auditor FP#5 vs SUIZERO SUI-REEN-*; move-auditor APT-21 | Three separate truths: no EVM-callback reentrancy (Sui/Aptos classic); PTB state-inconsistency reentrancy (SUI-02); closure-callback reentrancy (Aptos ≥2.2, APT-21). Rename the class per-chain. |
| 2 | Capability `store` ability | move-auditor 1.2 (deny) vs move-auditor-skills V5 (allow-with-policy) | Rule: no `copy` ever; `store` only with explicit, audited transfer policy; `key`-only + module-controlled transfers is the safe default. |
| 3 | Admin-origin latent DoS severity | move-auditor 12.2 (High/Critical by victim) vs move-auditor-skills (admin-only = do-not-report) vs hydration FP-007 (retroactive harm carve-out) | All three converge on "who is blocked and what is blocked": adopt move-auditor's rule; keep the others' carve-outs as FP guards. |
| 4 | Saturating arithmetic | safe-solana-builder §3.1 (never) vs hydration FP-002 (intent-dependent) | Checked math on balances/shares always; saturating only on bounded counters with documented intent. |
| 5 | Confidence representation | move-auditor (signal strength, 2-category corroboration) vs v2 family (100 − deductions) | Use numeric score internally (interop with agents), render as confirmed/likely/needs_review with severity caps externally. |
| 6 | Trusted-setup / admin-power findings | zk-skills Gate 3 demotion ladder vs EVM skills' centralization tiers | Add a "privilege demotion ladder" stanza to the unified judge: privileged-only trigger → demote unless an unprivileged amplifier or retroactive user harm is named. |
| 7 | Tool-first vs LLM-first | GPTScan/SUIZERO/weasel (tool proposes) vs audit skills (LLM proposes, judge disposes) | Run both directions: deterministic pre-pass to seed candidates; LLM lenses to discover; 4-gate judge as the common sink. |
| 8 | "assert is not a constraint" | zk-skills mantras vs zk-skills safe-patterns (legitimate compile-time assert) | Mirror every security-relevant `assert` with a constraint gadget (V-D5); flag unmirrored asserts only. |
| 9 | Retention of Low/Info findings | sui-move-skill (keep code-backed) vs move-auditor (severity discipline, drop cosmetic) | Keep Low/Info when code-backed AND security-relevant (observability, replay surface, liveness); drop "same value, different error code" class. |
| 10 | Static-tool accuracy claims | SUIZERO "85% accuracy" badge without shipped VALIDATION_REPORT.md | Never trust tool severities; treat every tool hit as a candidate through the judge. |

---

## 14. Unified Skill Blueprint (cluster-4 recommendation)

A unified non-EVM security skill should be assembled as follows:

**Layer A — core methodology (per chain):**
- Move/Sui/Aptos: `move-auditor` 8-phase workflow + signal router + FP catalog + SUI/APT/DEFI patterns; add sui-move-skill's regression matrix as Phase 0.5; add OZ review-sui type-authority check.
- Solana: safe-solana-builder §1–§31 as the checklist; solana-token-extensions-security as the Token-2022 lens; add a Solana judge stanza (CPI reload, PDA bumps, rent).
- ZK: zk-skills circom-auditor (slices, mantras, mental-tool protocol, R1CS judge).
- Substrate (optional branch): hydration cl0wdit + FP catalog + substrate vectors.

**Layer B — unified judge (v2 lineage):** 4 gates, numeric confidence with severity caps, single-pass protocol, per-chain Gate-3 stanzas, trusted-party demotion ladder, `group_key` dedup with detector provenance, composite chains, lead promotion rules.

**Layer C — validation mechanisms:** evidence-source tags + mock rejection (move-auditor), devil's advocate + kill questions + counterfactual-fix test (move-auditor), false-positive challenge questions (sui-move-skill), separate triage agents (zk-skills), PoC rules (weasel).

**Layer D — tool integrations:** SUIZERO (Move pre-pass), weasel/GPTScan (EVM pre-pass, rule-DSL), `sui move build`/`test` log analysis (move-auditor §13), CI gates; post-finding PoC/report skills.

**Layer E — reference material:** move-auditor defi/*.md, DESIGN-L1..L4, hydration attack vectors + FP-001..010, token-2022-patterns, zk 48-vector slices, safe-solana-builder 31 sections.

**Layer F — ops/validation:** BattleChain battle-testing stage (solskill), circuit-breaker incident playbook (hydration), `security-checklist.md` deliverable (safe-solana-builder).

### 14.1 Final classification summary

| Repo | Classification |
|---|---|
| `move-auditor` | **Core methodology (Move/Sui/Aptos)** + reference material (DeFi patterns, anti-FP engine) |
| `move-auditor-skills` | **Judge mechanism** + specialized sub-skill (Sui, parallel agents) |
| `sui-move-skill` | Specialized sub-skill (Sui) + **validation mechanism** (regression matrix, evidence thresholds) |
| `SUIZERO` | **Tool integration** (Move bytecode scanner; treat outputs as candidates) |
| `safe-solana-builder` | **Build-time guard** + reference material (Solana ruleset) |
| `solana-token-extensions-security` | Specialized sub-skill + reference material (Token-2022 lens) |
| `solskill` | Tool integration / validation mechanism (BattleChain ops; EVM dev standards) |
| `zk-skills` | **Core methodology (ZK/circom)** + **judge mechanism** (mental-tool protocol) |
| `weasel` | **Tool integration** (EVM scanner + PoC/validate/report skills) |
| `GPTScan` | Tool integration (EVM hybrid; rule DSL + two-stage prompting to preserve) |
| `hydration-node` | Core methodology (Substrate) + judge mechanism + reference material (FP catalog) + incident playbook |
| `openzeppelin-skills` | Build-time guard + specialized sub-skill (Sui integration review) |

**Single highest-value export per chain:** Move → the SUI-23 stale-package ritual + 12.1 abort-before-checkpoint deadlock; Solana → CPI `reload()` + reward-debt settlement + duplicate-account constraints; ZK → the declarative "what does the constraint system still ALLOW?" doctrine; Substrate → the known-false-positive catalog format; tooling → GPTScan's vuln-as-data rule schema and weasel's PoC discipline.




















