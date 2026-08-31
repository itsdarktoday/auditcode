# Cluster 3 — Validation & Judging Mechanisms: Deep Extraction Report

**Scope.** This report extracts the strongest, most reusable techniques for **vulnerability VALIDATION**: judging findings, eliminating false positives, building PoCs, fuzzing/invariants, scoping/recon, and known-issue detection from 11 repositories under `/home/nishan/ultimate-web3-security/sources/`:

`The-Judge`, `K.I.T`, `foundry-poc-mainnet-fork`, `trident-fuzz-skill`, `digger`, `finite-monkey-engine`, `scoping-bee`, `claudit`, `claude-bug-bounty`, `plamen`, `web3-skills` (contract-auditor / client-auditor / exploit-investigator).

For each repository: (1) contribution, (2) the 10–20 most valuable concrete techniques/gates worth preserving (quoted verbatim or nearly so), (3) contradictions with sibling methodologies, (4) gaps, (5) classification in a unified taxonomy:

> **core methodology** / **specialized sub-skill** / **reference material** / **tool integration** / **validation mechanism** / **judge mechanism**

A synthesis of cross-repo contradictions, a unified pipeline proposal, and a consolidated gate library close the report.

---

# 1. The-Judge — adversarial false-positive filter with final verdicts

## 1.1 Contribution
A multi-stage, multi-agent **judge** that consumes one finding (or a CSV batch) plus a codebase and returns `VALID`, `INVALID`, or `DOWNGRADED` with code-line evidence. Explicit purpose: "A high-accuracy false-positive filter for AI-generated web3 security findings". Benchmarked as "significantly reduc[ing] false-positive rates from upstream AI auditors while preserving real findings."

## 1.2 Most valuable techniques

### 1.2.1 The pipeline shape (adversarial duality + early exits)
```
STEP 1 (sweep: verify location, code, internal consistency)
STEP 2 (roles: does the attack reduce to "trusted role abuse"? → cap severity)
WAVE 1 (parallel): STEP 1.5 external research ∥ STEP 2.5 mitigation check ∥ STEP 3A selector ∥ STEP 4A generator
WAVE 2 (parallel, ONE message): STEP 3B (2× sonnet generic checkers) + STEP 4B (2× opus specific checkers)
STEP 3C: orchestrator — EARLY EXIT if ≥2 Step 3B checkers HOLDS
STEP 4C: neutral judge — fires on HOLDS, UNCERTAIN, or HIGH-confidence-reason FAILS (symmetric)
STEP 4D: aggregate verdicts; INVALID short-circuits to OUTPUT
STEP 5: severity calibrator — sets severity from the verified attack path (independent of claimed severity)
```
Key design decisions worth preserving:
- **Adversarial duality**: "every finding is tested by both a *generic* checker (covering common false-positive patterns from a library) and a *specific* generator that reads the actual code looking for issue-specific defenses, intentional design, MEV/atomicity constraints, implicit invariants, and economic edge cases."
- **Two-checker confirmation**: "early exit requires at least 2 of 3 checkers to independently confirm the same invalidation, preventing isolated checker mistakes from killing real findings." Step 3C: "EARLY EXIT requires BOTH Step 3B checkers to return `HOLDS` (unanimous agreement — this prevents false negatives from a single checker mistake)." Weak evidence from either checker → "discard that invalidation, note it as `OVERRULED`… any overrule breaks unanimity — no early exit."
- **Anti-hallucination guard**: "checker prompts forbid making confident claims about external protocol behavior from training data. Step 1.5 does live WebSearch verification of any external claim and caches results per session."
- **Symmetric judge**: fires on HOLDS *and* UNCERTAIN *and* high-confidence FAILS — never defaults to VALID.
- **Severity calibration decoupled from claim**: Step 5 sets severity from the verified attack path, independent of the reporter's claimed severity.
- **Duplicate filtering**: "Orchestrator filters Step 4A reasons against Step 3A's 4 selections (drop duplicates)" — the generator gets the full library and is told to go *beyond* its categories.

### 1.2.2 The Invalidation Library — generic rejection/downgrade catalog
Each reason is an ID-coded, self-contained card; the Step 3A selector "picks the 4 most applicable reasons (ranked)… The top 2 are verified by checker agents; the bottom 2 are passed to the final judge as considered alternatives." Categories (worth preserving as a unified gate library):

| Category | Codes |
|---|---|
| UNREALISTIC_PREREQUISITES | UP-1 extreme token decimals; UP-2 attacker holds >50% supply; UP-3 specific block.timestamp/number; UP-4 unrealistic initial deposit; UP-5 multiple low-probability events coincide |
| COST_EXCEEDS_PROFIT | CP-1 "total gas used × gas price vs. profit. If gas ≥ profit under normal gas prices, the attack is economically irrational"; CP-2 flash-loan fees (0.05–0.09%) unaccounted; CP-3 slippage/infinite-liquidity assumption; CP-4 capital lockup opportunity cost; CP-5 sustained multi-block spending |
| DESIGN_TRADEOFF | DT-1 intentional gas optimization; DT-2 no better alternative model; DT-3 limitation documented in design; DT-4 fix breaks composability/core functionality |
| EXISTING_GUARD | EG-1 access control; EG-2 reentrancy guard/CEI; EG-3 minimum-amount threshold; EG-4 pause mechanism; EG-5 input validation |
| UNREACHABLE_STATE | US-1 state combination prevented by invariant; US-2 previous op always resets the variable; US-3 initializer prevents zero-state; US-4 intermediate check blocks multi-step sequence |
| SELF_HARM_ONLY | SH-1 only own balance affected; SH-2 grief requires permanently locking own funds; SH-3 outcome equivalent to donation |
| DUST_IMPACT | DI-1 1-wei bounded; DI-2 error doesn't compound; DI-3 below minimum transferable amount; DI-4 within <0.01% DeFi tolerance |
| TIMING_IMPOSSIBLE | TI-1 same-block multi-tx ordering control; TI-2 MEV protection; TI-3 timelock > attack window; TI-4 oracle heartbeat keeps price fresh |
| SPEC_COMPLIANT | SC-1 matches EIP/ERC exactly; SC-2 docs explicitly describe it; SC-3 standard across implementations (first-depositor inflation, rounding direction) |
| INCORRECT_MATH | IM-1 profit calc omits fees; IM-2 assumes linear scaling but capped; IM-3 wrong decimals/precision; IM-4 theoretical max presented as realistic |
| ALREADY_MITIGATED | AM-1 separate function resets state; AM-2 timelock delay; AM-3 circuit breaker/rate limit; AM-4 monitoring + pause |
| OUT_OF_SCOPE | OS-1 test/mock/example only; OS-2 external dependency; OS-3 unreachable internal path; OS-4 deprecated component |

### 1.2.3 Issue-specific generator prompt (what goes *beyond* the library)
The 4A generator "MUST NOT propose reasons that fall into the library's categories. Focus on: Implicit invariants enforced by code outside the issue's narrow scope; Concrete economic edge cases with real numbers; Atomicity / MEV / frontrunning constraints on the attack sequence; Intentional design (NatSpec, calling context, internal-only helpers); Interaction effects between the affected function and other protocol components." Its checklist: compute attacker profit vs cost with real numbers; gas costs for the full attack sequence; MEV/frontrunning that would preempt the attack; timelock/delay giving defenders time; whether the described tx sequence is actually executable atomically; state changes from other users' normal operations that would disrupt the attack.

### 1.2.4 Context inputs + batch bookkeeping
- Single mode prompts once for protocol docs, role-trust file, audit scope; cached in `.validation_context/` and reused across runs.
- CSV mode: columns `Number`, `Title`, `Summary`; "process the batch in parallel waves of 5 issues at a time"; "Inter-issue observations accumulate" in `validation_notes.md` — cross-issue notes feed later validations (duplicate suppression and shared root-cause detection).
- Output discipline: per-issue full trace `validated_issues/ISSUE-{N}.md` (single) or `validation_results/ISSUE-{id}.md` (CSV).
- Model routing: opus for generator/specific checkers/judge, sonnet for selector/generic checkers — cheaper models on mechanical catalog matching, expensive ones on adversarial reasoning.

## 1.3 Contradictions
- **Admin/role findings**: The-Judge *caps severity* on trusted-role abuse; `claude-bug-bounty` *kills* them outright ("Admin can do X = not a bug"); `plamen` downgrades only *fully-trusted* actors and explicitly does NOT downgrade semi-trusted ones. Three different dispositions for the same precondition.
- **Execution evidence**: The-Judge verdicts rest on static re-reads ("Use `Read` to independently verify the cited code references") — no PoC execution. Conflicts with `plamen`'s hard rule that only `[POC-PASS]`/`[MEDUSA-PASS]` is ground truth for CONFIRMED and with `digger`'s "no evidence, no claim".
- **Internal tension**: the anti-hallucination guard forbids training-data claims about external protocols, yet the invalidation library itself is a corpus of empirical generalizations ("Most real-world tokens use 6 or 18 decimals", "flash loan fees typically 0.05-0.09%") — checker agents are instructed to apply training-data-like priors. The resolution (checks must be confirmed against *this* code) is implicit.
- **Verdict taxonomy collision**: `VALID/INVALID/DOWNGRADED` vs `plamen`'s `CONFIRMED/PARTIAL/REFUTED/CONTESTED` vs `digger`'s typed severity/confidence/stage enums vs `K.I.T`'s `known/possibly-known/new`. No mapping layer exists.

## 1.4 Gaps
- Requires Opus 4.x API access; ~7 min/finding on the deepest path.
- Single-mode asks the user for role-trust and scope files — verdict quality depends on inputs an automated pipeline may not have.
- No mechanical PoC, no fuzz harness integration, no storage-layout/toolchain checks.
- Benchmark methodology/results not shipped in repo (claims only).

## 1.5 Classification
**Judge mechanism** (core). Its *invalidation library* is the best-documented generic rejection catalog found anywhere in this cluster and should become shared **reference material** for every other judge.

# 2. K.I.T (Known Issue Triager) — canonical known-issues register + duplicate triage

## 2.1 Contribution
Builds a single canonical `known-issues.json` register from heterogeneous audit sources (local files, folders, PDFs, URLs, GitHub repo/folder URLs) and answers "is this new finding already known?" via a staged LLM contract. Host-agnostic: Claude Code `/kit`, Codex `$kit`, direct CLI over one shared Python engine.

## 2.2 Most valuable techniques

### 2.2.1 Staged (script prepares, LLM decides) architecture
`prepare-build` downloads/normalizes sources and stages a JSON state; the host LLM fills `source_results`; `finalize-build` writes the canonical register. The Python engine explicitly "does not make model judgments. It prepares source text and staged JSON contracts. The host model is responsible for extraction, deduplication, and duplicate decisions according to the staged contract."

### 2.2.2 The `llm_contract` — extraction + duplicate rules (verbatim-worthy)
- **finding_extraction rules**: "Do not merge multiple findings into one." / "Do not invent findings that are not supported by report_text." / "Keep wording close to the source when summarizing." / "If the input is already a single issue, return exactly one finding." Required fields: title, summary, root_cause, impact, affected_component, severity, evidence_snippet.
- **duplicate_check verdicts**: `known | possibly-known | new`.
- **decision_rules**: "Return known only when the underlying root cause, affected surface, and impact are materially the same as an existing known issue." / "Return possibly-known when there is a plausible match but the evidence is not strong enough for known." / "Return new when the finding differs in bug class, exploit path, preconditions, or impact in a way that makes it a separate issue." / "Do not match on component name alone." / "Do not match on severity alone." / "Wording differences do not matter if the underlying issue is the same." / "Explain why the closest match is or is not the same issue."
- **comparison_dimensions**: root_cause, affected_component, exploit_path_or_preconditions, impact, severity_context.
- **parallelization**: "If more than one finding is identified and delegation is available, spawn exactly one worker per finding… Do not batch multiple findings into one worker. After all workers finish, merge their outputs into one final ordered result list."

### 2.2.3 Operating rules (fail-closed, no guessing)
- "Treat `known-issues.json` as the only canonical artifact."
- "Do not use deterministic fallback for build or check. If the staged LLM data is missing, fail instead of guessing." (Enforced in code: `require_llm_canonical_issues` raises on missing/empty `canonical_issues`.)
- "Collapse issues when the underlying root cause, affected surface, and impact are materially the same even if wording differs. Keep issues separate when they only share a component or severity but differ in bug class or exploit path."
- "If a duplicate decision is borderline, return `possibly-known` and explain the ambiguity instead of forcing a collapse."
- "If extraction quality is weak for a source, record a warning instead of inventing structured findings."
- Canonical fields preserve: title, summary, root cause, impact, affected component, **aliases from source reports**, source report references, source locations, evidence snippets (whitespace-collapsed, truncated 300 chars, confidence defaulting to `medium`).

## 2.3 Contradictions
- **Known-ness vs validity**: K.I.T judges *duplication against prior reports*, never technical validity. A "known" verdict says nothing about whether the underlying issue is real — orthogonal to The-Judge/plamen. Pipelines that treat "known" as "rejected" (common in bug bounty triage) would silently drop valid findings.
- **Lookup source**: K.I.T builds a *private* register; `claudit` queries the *public* Solodit DB live; `plamen`'s RAG sweep uses a local vuln-db MCP with WebSearch fallback (`site:solodit.xyz`). Three incompatible prior-art sources; only K.I.T's is versioned/auditable offline.
- K.I.T's "fail instead of guessing" vs `plamen`'s fallback chain (MCP → similar findings → WebSearch → score 0.3 floor) — plamen degrades gracefully, K.I.T refuses.

## 2.4 Gaps
- No severity re-assessment or validity judgment of register contents; garbage-in-garbage-out register.
- Python 3.11+; PDF extraction quality varies; GitHub inputs need network.
- No mapping of severity scales between source reports (only normalized severity strings).

## 2.5 Classification
**Validation mechanism — known-issue detection / dedup** (triage support). The `llm_contract` and fail-closed rules are directly reusable as a spec for any "is this new?" gate.

# 3. foundry-poc-mainnet-fork — end-to-end mainnet-fork PoC construction

## 3.1 Contribution
Teaches an agent to write ONE Foundry test that reproduces a real vulnerability against real deployed contracts on a forked EVM chain, end-to-end: "from the action that first triggers the vulnerable state, through every on-chain step in between, to the final realized impact." Strictly scoped: NOT Hardhat, NOT local mocks, NOT fuzz harnesses, NOT non-EVM.

## 3.2 Most valuable techniques

### 3.2.1 Anti-anchoring reading order (the most distinctive rule)
"The order in which files are read shapes Claude's reasoning. Reading an existing PoC before classifying the finding anchors output to that PoC's structure and overrides the skill's rules in practice. Reading the finding first is not optional." Concrete mandates: read the finding to completion before any other file; "Do not read any file in the target PoC directory… until the finding is classified and the causal chain is written out"; "If a file with the planned output name already exists in the repo, treat it as untrusted… Stale or prior-session PoC files may encode causal-chain choices that violate the skill's rules. Do not anchor on them." Reference tests are read only at step 6, for *surface style* only — "Never imitate their fork-block choice, starting actor, or causal-chain structure."

### 3.2.2 Finding classification (a) / (b) / (a+b)
- (a) vulnerable state already exists / reached by block progression alone (e.g., `Example_FreezeHistorical.t.sol` — no causal chain to reproduce).
- (b) a causal chain of actions by a real actor produces the harm (e.g., decimals mismatch → mint inflated shares → drain).
- (a+b) both.
Classification is "stated out loud to the user before coding" and drives where the test starts: "For (b) or (a+b) findings, the test starts from an actor currently in the safe state, not from an already-impacted actor."

### 3.2.3 Required inputs — stop and ask, never guess
1. Vulnerability description (root cause, attack path, impact); ask for the full finding if summary-level. 2. Chain (explicit list). 3. Fork target: `latest`, specific block, or timestamp — "if timestamp, ask the user to convert it to a block number, do not guess." 4. Real deployed addresses for every contract in the attack path, labeled by role. 5. RPC guidance for archive state: "Public RPCs like publicnode often lack archive data; drpc.org, mevblocker.io, and eth-pokt.nodies.app retain broader history." 6. Existing test files for style. 7. Severity gate: "proceed for High, Medium, Critical; for Low or Info, warn the user that a PoC may not be warranted and confirm before proceeding."

### 3.2.4 Hard rules — the causal-chain integrity code
- Foundry only; `vm.createSelectFork` is the **first statement in `setUp()`**.
- "Every protocol contract is bound as a named `constant` real address."
- "No mock, stub, or minimal reimplementation is declared."
- "Every step in the causal chain is executed through the real contract that performs it on-chain, with the caller that performs it on-chain."
- **"No `deal`/prank combination bypasses a pipeline the finding says funds should flow through."**
- "Any shortcut around a genuinely infeasible step is documented in a single comment naming what is simulated."
- "The test ends at the realized impact, not a theoretical midpoint. Final assertions encode the end-state of the vulnerability."
- Anti-noise output rules: banned words, no em-dashes, no filler comments; "Every `console2.log` prints a labeled value"; "Assertion messages are two to five words, label-style, no 'must', no prose"; "No invariant is proven twice in the same test"; "The test name describes the vulnerability, not the test action"; run command uses `-vvvv`.
- Output = exactly 3 things: complete test file, exact `forge test` command with env vars + `-vvvv`, and "Two or three sentences explaining what the passing assertions prove about the vulnerability and the end-to-end impact." No JSON wrapper, no preamble.

## 3.3 Contradictions
- **Shortcuts**: `claude-bug-bounty`'s PoC template uses `deal(...)`/`vm.startPrank`/`assertGt(..., "Exploit failed")` — precisely what this skill bans as chain-bypass. The two skills produce structurally different PoCs for the same finding.
- **Skip policy**: `plamen` Phase 5 allows structured skips (`EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS`, `[UNPROVEN-EXTERNAL]` stamp); this skill has no skip path — it blocks on missing inputs instead. Complementary but conflicting in automation: plamen never halts the audit, this skill never guesses.
- **Mock policy**: plamen permits mocks to *confirm* (never REFUTE) and tags evidence `[MOCK]`; this skill bans mocks from the causal chain entirely.

## 3.4 Gaps
- EVM/Foundry only; single-chain (no cross-chain relay PoCs); no fuzz/invariant mode; no severity calibration; assumes the user supplies addresses and archive RPC.

## 3.5 Classification
**Validation mechanism — PoC construction** (specialized sub-skill for proof-grade reproduction). The reading-order, classification, and no-shortcut rules are the strongest anti-anchoring/anti-fake-proof discipline in the cluster and should gate *any* PoC-producing agent.

---

# 4. trident-fuzz-skill — invariant-driven stateful fuzzing (Solana/Trident)

## 4.1 Contribution
A 5-phase skill (setup → invariant mapping → construction → validation → analysis) for building Trident v0.12 stateful fuzz campaigns for Solana/Anchor programs, plus a progressive 4-stage methodology (Foundation / Integration / Scenario / Temporal) and an explicit "sufficiency" checklist. Positioning is explicit: "Not a crash fuzzer — it's **invariant-driven stateful fuzzing** that proves properties hold across all reachable states."

## 4.2 Most valuable techniques

### 4.2.1 ROI triage before building anything
High ROI: numeric-range inputs; cross-program shared state; commutative/associative operations; post-event operations. Low ROI/architectural blockers: "Instructions where each input requires a unique pre-initialized PDA (e.g., borrow amount determines tick, tick is a PDA that must exist)… Random inputs need random PDAs — impractical"; pure admin/config; stateless programs. Rule: "When you hit a low-ROI path: Don't force it. Scope the campaign to what CAN be fuzzed effectively… and note the gap for manual audit."

### 4.2.2 Expectations calibration (anti-false-confidence)
- "**Building a valid protocol state** (the hard part — Phase 1 is 60% of the work)."
- "**Most flows will revert.** This is expected… A 40-60% success rate is ideal."
- "**'No violations found' is the likely outcome.** Well-audited code rarely has bugs that random fuzzing catches. The value is in the confidence gained and the regression safety net."

### 4.2.3 Invariant sourcing & detection scopes (Phase 2)
Priority order: (A) existing invariant table from a prior audit in the exact format `| # | Invariant | Derived From | Fuzzable? | State Reads Needed | Detection Scope |` — "If this table exists, use it directly"; (B) audit findings → **regression invariants** ("What state was incorrect? That's the invariant (negated)"); (C) state relationship patterns — accounting identity (`total_borrow == sum(tick.raw_debt)`), bitmap/flag sync, dust/rounding bound, cross-protocol conservation (`TR.total_supply >= position.amount`), ordering constraint, token conservation; (D) implicit invariants verified by transaction success (tick computation, PDA seeds, signer authority) — "Document these but don't assert them in `end()`."

**The flagship lesson**: "Cross-protocol invariants (T1/T2/B1) will NOT catch within-protocol bugs where both sides of a CPI record the same wrong number. Example: stale dust causes wrong repayment amount, but both vault and liquidity layer record the same wrong CPI amount consistently — cross-protocol invariants hold, the bug is invisible. You need **within-protocol invariants** to catch these." This CPI-consistency insight is the single most reusable invariant-design principle in the cluster.

### 4.2.4 Invariant sensitivity & durability tests (anti-tautology gates)
Three failure modes that make an invariant insensitive: (1) **dead read** — wrong pubkey/offset reads a zeroed account (`assert_eq!(0, 0)` always passes); (2) **tautological comparison** — both sides from the same field/read; (3) **unreachable state** — flows never reach the condition. Test methods:
- Approach A (temporary): inject a known-false assertion `assert_eq!(vault_state.total_borrow, 999999, "E2 sensitivity check")` — if it doesn't panic, the state read is broken.
- Approach B (permanent): first-iteration non-triviality check — `if self.iteration == 1 && self.success_count > 0 { assert!(vs.total_supply > 0, "SENSITIVITY: total_supply is 0 after successful deposits — state read is broken") }`.
Durability classes: **Permanent** (keep forever) / **Conditional** (review on upgrades) / **Bug-specific** ("When the bug is fixed, they'll fail — and that's correct behavior. Replace them with a general invariant") / **Temporal** (gate on conditions).

### 4.2.5 Validation gotchas (Phase 4)
- "Trident's parallel mode routes panics through a progress bar, NOT stderr. Redirecting stderr (`2>file.txt`) produces an empty file even when panics occur." Debug mode: `TRIDENT_FUZZ_DEBUG=0000000000000000 ./target/debug/fuzz_0 2>&1 | head -200`.
- Flow health: a flow that always reverts is either expected (withdraw > balance) or a setup bug (PDA seed mismatch). "Expected reverts = healthy. The fuzzer is exploring boundary conditions. Unexpected errors = setup bug."
- Scale-up gate: 10×10 validation run → green/yellow/red interpretation → only then `FuzzTest::fuzz(1000, 100)` with `--release`.


---

### 4.2.6 Violation triage tree (Phase 5) — the most reusable piece
```
Violation found
  |-- Is the invariant correct? (rounding/edge cases?) No -> fix invariant, re-run
  |-- Reproduce with fixed seed: TRIDENT_FUZZ_DEBUG=<seed>
  |-- First iteration? Yes -> likely setup artifact (check init ordering)
  |-- Walk state: before state → triggering flow → breaking change → legitimate state?
  |-- Classification: Cross-protocol -> High severity (shared state corruption);
      Within-protocol -> assess fund loss; Rounding/dust -> often acceptable (check magnitude)
```
Panic classification: `overflow/underflow` → "**Likely real bug**"; "**Math panics are often real bugs.** Reproduce and investigate before dismissing." vs `range end index`/`AccountLoaderMissingAccountLoader` → setup bug.

### 4.2.7 Sufficiency checklist (what "done" means)
Coverage (every in-scope instruction has ≥1 flow; success+revert paths; cross-protocol interleaving; adversarial transitions) / Invariant quality (multiple detection scopes; sensitivity-tested; non-triviality guards; no trivially-true invariants) / Iteration depth ("1000+ for Foundation, 200+ for Scenario"; multiple flows succeed per iteration) / Gap documentation ("Coverage matrix explicitly lists what was NOT tested; Each gap has a risk assessment (high/medium/low); High-risk gaps have a documented alternative") / Reproducibility (seed + commands; deterministic setup). Explicitly NOT sufficiency: "100% code coverage" (Trident is not coverage-guided), "found a bug", "ran N hours", "tested every instruction." Terminal output: the "honest assessment" paragraph — "If you can't write this statement, your fuzzing work is not yet sufficient."

### 4.2.8 Progressive stage design
Each stage's blind spots inform the next: Foundation misses cross-program corruption; Integration misses CPI-consistent bugs; Scenario misses time-dependent bugs; Temporal misses dynamic-PDA paths. Key question after each pass: "**If there were a bug in each of these categories, would this campaign have caught it?**"

## 4.3 Contradictions
- **Fuzz evidence weight**: trident says fuzz campaigns mostly yield "no violations" and are for confidence/regression; `plamen` treats `[MEDUSA-PASS]` (a fuzz counterexample) as **proof-grade, same weight as `[POC-PASS]`**; `digger` explicitly caps fuzz-artifact evidence below "confirmed vulnerability" ("Confidence ceiling is `invariant_failed`… This is evidence for triage, not a confirmed vulnerability"). Three different epistemologies for the same artifact.
- **Within-protocol assertion need** contradicts naive invariant guidance elsewhere (e.g., claude-bug-bounty's property checks) that checks only top-level balances.

## 4.4 Gaps
- Solana/Trident only; no EVM fuzz skill in this repo (Echidna/Medusa equivalents live in plamen/digger's CLI).
- Requires `anchor build` passing and Trident v0.12; API file must be swapped per version.
- Acknowledges architecturally unfuzzable paths but offers no formal fallback beyond "manual audit."

## 4.5 Classification
**Validation mechanism — invariant/fuzz testing** (specialized sub-skill for Solana). The invariant-sourcing, sensitivity/durability tests, violation triage tree, and sufficiency checklist are chain-agnostic and should be promoted into a shared fuzz-methodology core reused by EVM (Echidna/Medusa) harnesses.

# 5. digger — deterministic, evidence-gated triage engine (EVM/Solana/op-layer)

## 5.1 Contribution
An evidence-gated, deterministic (non-LLM core) security triage engine with an MCP agentic interface. Tagline: "AI can suspect, Digger proves." Outputs engine-certified findings with typed severity/confidence/stage labels and function-symbol provenance; also ships an intent verifier and fuzz-evidence ingestion. Explicit commitments: "**Hypotheses, not verdicts.** Findings are ranked hypotheses with explicit confidence — never 'confirmed vulnerabilities'"; "**Evidence-gated.** No claim ships without a concrete evidence chain (line / call path / storage slot). No evidence, no claim"; "**Deterministic core.** Same input → same output, every run."

## 5.2 Most valuable techniques

### 5.2.1 Typed enums, never strings
"Findings carry typed severity (info/low/medium/high/critical), confidence (experimental/graduated), and stage (shadow/advisory/armed) enums — never strings. Evidence IDs are populated from detector provenance and survive the MCP `list_findings` round-trip." Kills the free-text severity class of AI-report bugs at the schema level.

### 5.2.2 `validate_assistant_output` — deterministic claim checking
Read-only MCP tool that "Deterministically validate[s] structured claims against engine truth. Input: `{scan_id, claimed_findings, prose?}`." It "catches promotion attempts (severity/confidence/stage/finding injection)" — an agent that inflates Medium→High or invents a finding is mechanically rejected. Sample verification shows the failure taxonomy: `status: insufficient_evidence`, `evidence_satisfied: []`, `evidence_missing: [...]`, `required_next_steps`, `is_finding: false`. Honest scoping: "The validate tool compares claims against engine-emitted findings only — it cannot assess novel attack vectors or logic not present in the scanned source."

### 5.2.3 Honest capability labeling (graduated vs experimental)
"**Graduated confidence (production-ready):** EVM: price oracle manipulation, readonly reentrancy; Solana: access control bypass, unvalidated CPI, type cosplay, unchecked account owner. **Experimental confidence (structural observation, not a full audit):** Operational-layer (TS/Node): … These detectors use syntactic proxy analysis — they match structural patterns in handler source code, not runtime behavior." And: "Treat findings as leads for expert review." Reusable pattern: every detector should carry a maturity label and a confidence ceiling.

### 5.2.4 Fuzz evidence ingestion with confidence ceilings
`digger fuzz-maturity` — does a repo have real invariant-fuzzing infrastructure? "Confidence ceiling caps at `harness/config_present`. This is a maturity signal, not proof of a bug." `digger fuzz-evidence --tool foundry|echidna|medusa|crucible` parses failure artifacts: "Confidence ceiling is `invariant_failed` (no replay command) or `failure_replayed` (replay command present). This is evidence for triage, not a confirmed vulnerability." Explicit: "Digger does NOT run Crucible or generate harnesses."

### 5.2.5 Evidence requirements on hypotheses
Every hypothesis carries `evidence_requirements` (e.g., `["graph evidence", "IR verification"]`) and `status: requires_investigation` — a finding is a *claim needing proof*, and the proof type is named up front.

### 5.2.6 Egress consent gate (operational security)
"All network access from Digger is gated behind explicit user consent." `authorize_global(url, purpose)` on every HTTP call; trust store persists only `SCHEME://HOST` pairs "never full URLs or API keys"; `--no-network` hard-offline fail-closed; file mode 0600. A model for any agent tooling that fetches contract sources.

### 5.2.7 Intent verifier
Decodes calldata/EIP-712/Solana tx → plain English + risk levels Safe / Suspicious / Dangerous ("Known high-risk function (e.g., upgrade, mint, pause) with no guardrails"). Reports `is_finding: false` — "this is a decoded explanation, not a security finding."

## 5.3 Contradictions
- **Verdict authority**: digger refuses verdicts ("hypotheses, not verdicts"; "The engine decides verdicts; the assistant never does") while The-Judge and plamen produce final accept/reject verdicts. Digger implies a human/LLM final layer; the others automate it.
- **Fuzz evidence**: digger caps fuzz evidence below "confirmed"; plamen promotes `[MEDUSA-PASS]` to proof-grade. Direct conflict (see §4.3).
- **Novelty**: digger's validator "cannot assess novel attack vectors" — the opposite of The-Judge's issue-specific generator, which exists precisely to reason beyond catalogs.

## 5.4 Gaps
- Partial file:line spans for Solana/op-layer classes ("evidence is provenance-level, not full source-span proof"); `predicate_states` intentionally empty; MCP tools read-only; fuzz parsers CLI-only; no novel-vector analysis; op-layer detectors are syntactic heuristics.

## 5.5 Classification
**Tool integration + validation mechanism** (deterministic evidence gate; engine-truth validator for agent outputs). Its typed-enum schema, `validate_assistant_output`, confidence ceilings, and egress gate are the strongest *mechanical* anti-inflation/anti-hallucination layer found in this cluster.

---

---

# 6. finite-monkey-engine — hypothesis-space mining with LLM validation

## 6.1 Contribution
A research-grade, multi-language LLM vuln-mining engine (Solidity/Rust/Move/Go/C++, tree-sitter/ANTLR4) organized as Planning → Reasoning (Watcher/Reasoner/Ideator roles) → Dedup → Validation, with findings stored per-item in PostgreSQL (`project_finding`). Its philosophy documents are unusually candid about LLM failure modes and contain several mechanisms that generalize to any validation pipeline.

## 6.2 Most valuable techniques

### 6.2.1 Error-accumulation law (the most important insight in the repo)
"错误累积定律" — errors accumulate exponentially with pipeline complexity: at ~60-70% accuracy per LLM action, ~10 actions leave ~2% end-to-end accuracy; even at 99% per action, 30 actions leave ~73%. Therefore: "在 ai audit 领域内，要跳出 agent action link 的限制… 从'寻找正确答案'转向'管理可能性空间'" — **shift from 'finding the right answer' to 'managing the possibility space'**: `Code → possibility-space construction → vulnerability hypothesis cloud → validation convergence → deterministic conclusion`. Fewer, shorter chains; parallel hypotheses instead of sequential reasoning; a separate validation stage converges the cloud.

### 6.2.2 The finite monkey hypothesis
The LLM's hypothesis space is finite/convergent: 10 iterations produce 10 findings that cluster into ~5 categories, and further iterations rarely produce new ones — hence mining terminates and a bounded hypothesis set can be exhaustively validated. Implication for judges: enumerate the hypothesis cloud, then validate each; do not rely on iterative prompting alone.

### 6.2.3 Context funnel — validation needs full context
"不能让 llm 去验证一些它完全不知道的事情" (you cannot let an LLM validate what it hasn't seen). The engine builds a RAG-based "context funnel" extracting the code relevant to a specific vulnerability claim; validation runs against that funnel — not against the finding text alone. Mirrors The-Judge's Step 1 code-consistency sweep, implemented mechanically.

### 6.2.4 The validation prompt (ValidationCodexPrompt) — a complete verdict schema
A strong template for any validator agent:
- Workspace constraint: read only the workspace root; no assumptions about code/config/deployment outside it; read-only commands (rg/grep/find/cat/sed -n), no writes.
- Agentic workflow: "至少 3 次，最多 10 次" multi-step retrieval before concluding; trace callers/callees/state-update order/boundary conditions.
- **Docs-first**: check README/docs/spec/NatSpec to decide "design-intent vs vulnerability" before concluding.
- JSON-only schema: `status ∈ {pending|intended_design|false_positive|vulnerability|vuln_high_cost|vuln_low_impact|not_sure}`; `confidence ∈ {high|medium|low}`; `exists: bool`; `classification ∈ {vulnerability|non_vulnerability|uncertain}`; `impact`; `exploit_difficulty`; `reason` (2–5 sentences citing evidence); `evidence[] {file, locator, snippet≤30 lines, why}`; `doc_references[]`; `attack_preconditions[]`; `attack_path`; `mitigation`; `unknowns[]` (mandatory when `not_sure`).
- 判定口径 (judgment criteria): `intended_design` = documented expected behavior without a real abuse path; `false_positive` = finding's description contradicts code facts (condition doesn't exist, permission unobtainable, entry unreachable, variable uncontrollable, logic reversed); `vulnerability` = realistic exploitable path with concrete damage; `vuln_high_cost` / `vuln_low_impact` = valid but attenuated.

### 6.2.5 Watcher/Reasoner/Ideator roles with budgeted convergence
- Reasoner process output: `analysis_summary`, `checked_hypotheses`, `open_questions`, `next_actions` (retrievable keywords/files/variables — the most important product), `suggest_stop`.
- Watcher decides `continue | pivot | stop` against budgets (`max_more_rounds / time_limit_sec / no_progress_rounds`) and maintains `memory_store` with confirmed/rejected/open conclusions so dead ends are never re-mined.
- Every finding's `description` must include why it is *not* a false positive (permissions/preconditions/unreachability already excluded).

### 6.2.6 Neutral vs induced prompts (both modes exist — see contradictions)
- Early engine: the *assertive* prompt "这个代码里面有一个漏洞，请你把它找出来" ("there is a bug in this code, find it") triggered reasoning better than "is there a bug?" — an explicit, deliberate induction of hallucination for recall ("trigger, love, embrace hallucination" — then validate).
- `forward` branch: neutral audit-style JSON prompt, zero findings allowed ("允许输出零漏洞"), "不做诱导式'必有漏洞'提示词" — no inductive prompt; multi-vuln `vulnerabilities[]`; `gpt-5.2` with `response_format=json_object`; idempotent split into `project_finding` rows.

### 6.2.7 Hard-coded prior rules (vul_check_prompt) — blunt but documented
1. Overflow (Solidity ≥0.8.0) → "does not exist". 2. Reentrancy → "does not exist". 3. Mid-execution external insertion / atomicity → "does not exist". 4. Permission-controlled functions: "if the permission roles can be obtained, you still need to consider the vulnerability". 6. onlyOwner → "does not exist". 7. "Any vulnerability or risk that could cause potential losses is valid (even small losses)". These bake a domain prior directly into the checker — the exact opposite of The-Judge's design, which forbids training-data priors in checkers.

### 6.2.8 Data plumbing for validation at scale
Planning: business flows `Fi` × `rule_keys` Cartesian product → `project_task`; coverage repair until threshold (98% on a 1000-line project); task/finding separation so dedup/validation/export operate on single-vuln records; export filters `dedup_status != delete AND validation_status == yes`; breakpoint-resume states (`split_done/split_failed`); Foundry PoC generation integrated into Reasoning/Validation with confined workspace writes.

## 6.3 Contradictions
- **Induction vs neutrality (the sharpest cross-repo conflict in this cluster)**: finite-monkey's original philosophy *deliberately induces hallucination* for recall then validates; its own `forward` branch, `plamen`'s Reasoning (neutral prompts, zero findings allowed), and `digger` ("hypotheses, not verdicts") reject induction as precision poison. The-Judge sits between: it doesn't induce, but it adversarially attacks every claim.
- **Blunt priors vs code-driven judging**: "reentrancy → does not exist" and "onlyOwner → does not exist" contradict The-Judge (roles case-by-case, cap not kill) and scoping-bee/contract-auditor (reentrancy is a first-class surface). These priors are dataset-era artifacts and should not be copied.
- **Validation models**: detection=Claude, validation=deepseek o1 (cost/latency-driven) vs The-Judge (opus checkers + sonnet selector) vs plamen (opus verify) — no consensus, but all agree validation should use a *different* (often stronger/reasoning) model than detection.

## 6.4 Gaps
- Mostly Chinese-language docs; experimental/research status; heavy PostgreSQL dependency; PoC execution described as in-progress in planning docs; dataset-dependent priors that don't transfer to newer compiler eras.

## 6.5 Classification
**Judge mechanism + validation mechanism** (multi-role validation with a typed verdict enum). Reusable assets: error-accumulation law, possibility-space/convergence model, context-funnel requirement, ValidationCodexPrompt schema. The induced-hallucination prompt and blunt prior rules are *reference material for what not to copy*.

---

# 7. scoping-bee — pre-audit scoping with threat-intel gate and effort model

## 7.1 Contribution
Structured pre-audit scoping for Solidity and Solana/Anchor: source acquisition (GitHub/ZIP/explorer/address/local), a mandatory pre-scoping threat-intel scan with a blocking decision ladder, flow diagrams + trust tables, a weighted complexity rubric, attack-surface checklists, and a scope report with effort estimation at a configurable auditor pace.

## 7.2 Most valuable techniques

### 7.2.1 Threat-intel decision ladder (pre-scoping kill gate)
```
If CRITICAL findings → BLOCK immediately. Do NOT proceed under any circumstances.
If HIGH severity findings → STOP. Report findings. Ask user to review.
If MEDIUM severity findings → WARN. Show findings. Ask user to confirm proceed.
If only LOW/NONE → Proceed automatically to Phase 1.
```
Also: "**Always show the threat intelligence scan summary** in the scope report regardless of findings" and "**Do NOT include false positive counts** in the threat scan results. Only show the category checks and their pass/fail status. Mentioning false positive numbers can cause unnecessary concern." The scan covers 16 categories (token theft/rug vectors, governance exploits, dependency & supply chain, crypto abuse, runtime detection, etc.) each with a severity band.

### 7.2.2 Auditor pace + effort model
"Default audit pace is **350 nSLOC/day**." Pace table: 400 simple/well-documented; 350 default; 300 high complexity; 250 critical infra/bridges. "When presenting the final effort estimate, always state the pace used so the user can re-calculate if they adjust later." `base_days = total_nSLOC / AUDIT_PACE`.

### 7.2.3 Weighted complexity rubric (1–4 per metric, red flags auto-bump)
```
composite = (nSLOC × 0.25) + (extIntegration × 0.25) + (stateCoupling × 0.20)
          + (accessControl × 0.15) + (upgradeability × 0.15)
```
Tier mapping: 1.0–1.5 LOW → checklist review; 1.6–2.5 MEDIUM → vector scan; 2.6–3.5 HIGH → deep interrogation; 3.6–4.0 CRITICAL → "Deep interrogation + invariant extraction + PoC". Effort multipliers ×1.0 / ×1.3 / ×1.7 / ×2.2.
Notable **red flags** (each auto-bumps its metric to 3+): Solidity `delegatecall`/user-supplied call targets/cross-contract reentrancy; Solana user-supplied program accounts/`invoke_signed` with complex seeds/`remaining_accounts` iteration; state: sentinel values (0="unset"), monotonic claim pointers, write-once flags gating critical logic, cross-contract shared state; access: self-assignable roles, no two-step transfer, inconsistent modifier application, `tx.origin` auth; upgrade: `selfdestruct` in implementation, no storage gap, uninitialized implementation, admin changing core addresses without validation.

### 7.2.4 In-scope file discovery (framework-aware)
Solidity `find` excluding `test/tests/mock/mocks/script/scripts/node_modules/lib` plus `! -name '*.t.sol' ! -name '*.s.sol' ! -iname '*mock*.sol'`; Rust equivalent excluding `target/mod.rs/mocks`. Files classified Core / Interface / Library / Dependency.

### 7.2.5 Trust-assumptions table + flow diagram
Mermaid flow of value in/through/out with "a **Trust Assumptions** table mapping: From → To → Assumption → Risk if Broken." Solana adds PDA derivation flows, CPI targets, signer authority model. Explicit bans: "Do NOT output raw JSON for architectural context" and no duplicate "System Maps" section.

### 7.2.6 Attack-surface checklist (EVM 24 surfaces + Solana set)
Trigger-condition driven ("if any trigger matches, mark as `⚠️ INVESTIGATE`") — e.g., cross-contract reentrancy calls out "Read-only reentrancy (Balancer-style: state inconsistency exploited by reading intermediate state)"; oracle: "Spot price usage (manipulable in same TX via flash loans)", "TWAP window length (too short = manipulable)", "Stale oracle data (no freshness check on Chainlink `updatedAt`)", "Oracle decimals mismatch"; ERC20: fee-on-transfer, rebasing, missing return values, `decimals != 18`, zero-amount reverts, TUSD-style dual addresses, upgradeable tokens. The checklist "is used internally during scoping… The full matrix is **not** included in the final scope report."

## 7.3 Contradictions
- **Block-on-findings vs hypotheses**: scoping-bee *blocks the engagement* on CRITICAL threat-scan findings; digger and finite-monkey refuse final verdicts ("hypotheses, not verdicts") and would treat the same scan as leads. Scoping-bee presupposes high-confidence detection at scoping time.
- **Effort model**: nSLOC×pace is a throughput heuristic; no other repo models effort. Where plamen budgets *agents*, scoping-bee budgets *days* — not reconcilable into one cost model.
- **Pace assumptions**: the ×2.2 CRITICAL multiplier implicitly assumes complexity correlates with audit depth; plamen's Light/Core/Thorough modes reframe depth as a *choice*, not a derived quantity.

## 7.4 Gaps
- EVM + Solana only (no Move/Sui/Cosmos); threat scan is script-based; rubric is heuristic with no published calibration; no on-chain analytics (TVL, age, incident history) despite the threat-intel step.

## 7.5 Classification
**Core methodology — scoping/recon phase** (specialized sub-skill for the pre-audit stage). The complexity rubric, threat ladder, and attack-surface checklist are directly reusable as the scoping module of any unified audit pipeline.

---
# 8. claudit — live Solodit search MCP for prior-art checks

## 8.1 Contribution
An MCP server (`search_findings` / `get_finding` / `get_filter_options`) exposing Solodit's 20k+ audit findings to Claude Code/Codex/Cursor, plus a companion skill encoding query patterns and mandatory result formatting. Purpose: "find prior art, research vulnerability patterns, and compare against known issues from real audits."

## 8.2 Most valuable techniques
- **Prior-art gate before reporting**: "**Checking prior art**: Before reporting a finding, search for similar issues to reference." — a dedup/novelty gate backed by the largest public finding corpus.
- **Quality/rarity filters**: `advanced_filters { quality_score, rarity_score, user, min_finders, max_finders, reported_after, protocol_category, forked }`; `sort_by: Recency | Quality | Rarity`.
- **Novelty heuristic**: "High-quality solo findings (likely novel)" = `tags=["Oracle"], advanced_filters={ quality_score: 4, max_finders: 1 }`.
- **Query discipline**: "Start broad, then narrow with filters"; call `get_filter_options` first when unsure of valid values; broaden keywords when zero results.
- **Mandatory output format**: "Do NOT use tables. Do NOT omit links… You MUST include this URL for every finding" — `[SEVERITY] Title / Firm (Protocol) · Quality: X/5 · Finders: N / → https://solodit.cyfrin.io/issues/...`.

## 8.3 Contradictions
- **Prior-art source**: live Solodit API (key, network) vs K.I.T's local canonical register (offline, auditable) vs plamen's unified-vuln-db MCP + `site:solodit.xyz` WebSearch fallback. claudit has the richest corpus but zero dedup semantics of its own; K.I.T has semantics but a corpus limited to what you feed it.
- **Offline capability**: claudit cannot run offline; digger's design is fail-closed offline-first.

## 8.4 Gaps
- No dedup logic or verdicts — pure search; dependent on Solodit API stability; quality/rarity scores are Solodit's own opaque metrics.

## 8.5 Classification
**Tool integration — reference material search** (prior-art / known-issue detection support). Best used inside a K.I.T-style "is this new?" gate or a judge's RAG sweep, not as a standalone validator.

---


# 9. claude-bug-bounty — fast kill gates + web3 hunt checklist

## 9.1 Contribution
A bug-bounty command suite (mostly web2: `/triage`, `/validate`, `/report`, plus `/web3-audit`) whose validation gates are the most battle-tested "kill weak findings before writing a report" heuristics in the cluster. "Prevents N/A submissions that hurt validity ratio."

## 9.2 Most valuable techniques

### 9.2.1 The 7-Question Gate (`/triage`) — "First NO = kill it immediately"
```
Q1: Can I demonstrate this with a real HTTP request RIGHT NOW?    (else KILL)
Q2: Is this impact type accepted by the program?                   (else KILL)
Q3: Is the vulnerable asset owned by and in scope for the program? (else KILL)
Q4: Does this work without admin/privileged access?  ("Requires admin → KILL (99% of programs)")
Q5: Is this NOT already known/disclosed/documented behavior?       (else KILL)
Q6: Can I prove impact beyond "technically possible"?              (else DOWNGRADE)
Q7: Is this NOT on the never-submit list?                          (else KILL or CHAIN)
```

### 9.2.2 Cross-identity proof for auth findings
"If the bug class involves IDOR, BOLA, auth bypass, ATO, or privilege escalation, you must prove it across identities: Session A reading Session B's data; Fresh session repro; Anonymous vs authenticated delta. Blank answers fail this check."

### 9.2.3 Fast Kill Checklist + Conditional Kill chains
Kill immediately: "'Admin can do X' = not a bug"; "'Could theoretically lead to...' = no PoC = not a bug"; "Bug requires 3+ preconditions simultaneously"; "Finding is a missing header, missing flag, missing DMARC"; "SSRF with DNS callback only"; "Open redirect with no OAuth chain"; "Self-XSS"; "Introspection only"; "Rate limit on login/contact/search (Cloudflare covers it)".
Conditional kill (chain required): "Open redirect → OAuth code theft → ATO = report the chain… If you can't build the chain today → KILL IT."

### 9.2.4 Four pre-submission gates (`/validate`)
Gate 0 (30s): confirmed with real requests, in scope, reproducible from scratch, evidence captured. Gate 1 Impact (2m): "Can answer 'What does attacker walk away with?'"; "Real victim exists"; "No unlikely preconditions". Gate 2 Dedup (5m): Hacktivity + GitHub issues + 5 most recent disclosed reports + changelog. Gate 3 Report quality (10m): title formula "**[Class] in [Endpoint] allows [actor] to [impact]**", exact requests, actual-impact evidence, CVSS, 1-2 sentence fix.
Proof standards per class: "XSS → actual cookie value in exfil request, not just alert()"; "SSRF → response body from internal service, not just DNS callback"; "IDOR → actual other-user's private data in response, not just 200 status".

### 9.2.5 Web3 hunt economics (`/web3-audit` Step 0)
Pre-dive kill signals: "TVL < $500K → max payout too low for effort → SKIP"; "2+ top-tier audits (Halborn, ToB, Cyfrin, OZ) on simple protocol → SKIP"; "max_payout = min(10% × TVL, program_cap) → if < $10K → SKIP". Scoring to proceed (≥6/10): TVL >$10M +2; Immunefi Critical ≥$50K +2; no top-tier audit on current version +2; <30 days since deploy +1; hunted before +1; upgradeable proxies +1.

### 9.2.6 Ten-bug-class grep methodology with priors
Accounting desync (28% of criticals) — "For each early return in claim/redeem/withdraw functions: Which state variables are updated in the normal path? Are ALL of them also updated in the early return path?"; access control (19%) — "Does EVERY sibling function in a family have the SAME modifiers?"; incomplete path (17%) — function-family A/B state-change comparison; off-by-one (22% of highs) — "For EVERY `if (A > B)`: 'What happens when A == B?'"; oracle — "Is staleness checked? … Is Pyth confidence interval checked? (`require(conf * 10 <= price)`) … Is TWAP window > 1800 seconds (30 min)?"; ERC4626 — "Is there a `_decimalsOffset()` virtual shares defense against first-depositor attack?"; signature — "Does signed hash include: nonce + chainId + contract address?"; proxy — "`_disableInitializers()` in implementation constructor?".
Confirmation gate adapted to web3: "1. Can I demonstrate this with a Foundry test? … 5. Does my Foundry PoC actually run? (`forge test -vvvv`)".

## 9.3 Contradictions
- **Admin findings**: `/validate` Q4 kills admin-required findings for submission purposes; The-Judge caps severity; plamen reports with a downgrade note for fully-trusted actors. For *submission* triage kill is correct; for *audit reporting* kill is wrong — context decides.
- **PoC shortcuts**: its Foundry template (`deal()`, `vm.startPrank`, `assertGt(..., "Exploit failed")`) is exactly what foundry-poc-mainnet-fork bans ("No `deal`/prank combination bypasses a pipeline…").
- **Economics**: kill-by-TVL/effort gates are unique to claude-bug-bounty; digger and scoping-bee explicitly don't consider payout. Applying them inside an audit pipeline would silently scope out low-TVL-but-critical-infra targets.

## 9.4 Gaps
- Web2-centric commands dominate; web3 coverage is a single checklist command; no fuzz; PoC template minimal; triage targets submission-worthiness, not technical truth (kills real-but-unsubmittable findings by design).

## 9.5 Classification
**Validation mechanism — fast triage gates** (judge-adjacent). The 7-question gate, cross-identity proof, kill checklist, and 4 gates are the best *submission* filter in the cluster and transfer directly to web3 bounty workflows; the web3 checklist is a solid specialized hunting sub-skill.

---

# 10. plamen — deterministic audit pipeline with proof-grade verification

## 10.1 Contribution
The most complete validation machinery in the cluster: a V2 deterministic Python driver running an LLM audit pipeline phase-by-phase in isolated subprocesses (eliminating "context saturation → skipped steps" failure of single-conversation orchestrators), with typed evidence tags, 4-axis confidence scoring, mandatory PoC execution with a harm-assertion hard gate, chain analysis, RAG sweeps, skeptic-judge severity calibration, and a strict report template. Multi-language: EVM / Solana / L1 / Move / etc.

## 10.2 Most valuable techniques

### 10.2.1 Evidence tag hierarchy (the backbone — everything else references it)
| Tag | Meaning | Evidence-score |
|---|---|---|
| [PROD-ONCHAIN] | verified on-chain production behavior | 1.0 |
| [PROD-SOURCE] / [PROD-FORK] | production source / fork-verified | 0.9 |
| [MEDUSA-PASS] | fuzz counterexample found | 1.0 (proof-grade) |
| [CODE] | in-scope code trace | 0.8 |
| [DOC] | documentation/spec only | 0.4 |
| [MOCK] | mock/test evidence | 0.2 |
| [EXT-UNV] | external, unverified behavior | 0.1 |

### 10.2.2 Mock rejection rule (asymmetric evidence rules)
"**AUTOMATIC OVERRIDE**: If ANY evidence supporting REFUTED has tag [MOCK] or [EXT-UNV]: CANNOT return REFUTED; MUST return CONTESTED; Triggers production verification." Rationale: you can *confirm* a bug with a mock, but you can never *refute* one with a mock — the defense must be proven against production behavior. The verifier must fill an Evidence Audit table: `| Claim | Evidence Source | Tag | Valid for REFUTED? |`. `[DOC]` alone also cannot support REFUTED ("needs verification"). This asymmetry (confirm cheap, refute expensive) is the single best false-negative-prevention rule found anywhere.

### 10.2.3 Verdict taxonomy + precondition/postcondition modeling
`CONFIRMED / PARTIAL / REFUTED / CONTESTED`. Every finding carries: **Precondition Analysis** (if PARTIAL/REFUTED: Missing Precondition + type ∈ STATE/ACCESS/TIMING/EXTERNAL/BALANCE + why it blocks) and **Postcondition Analysis** (if CONFIRMED/PARTIAL: what conditions it creates, who benefits). These typed pre/postconditions are what the chain-analysis phase matches to build compound exploits — findings are modeled as state-transition producers/consumers, not text.

### 10.2.4 Material Harm mandate (anti-mechanism-reporting)
"**Material Harm** (MANDATORY): The concrete CONSEQUENCE in one sentence — not the mechanism, the harm. State WHO loses WHAT (specific user class + funds/privilege/liveness/accounting/integrity consequence)." "A finding whose only stated harm is a MECHANISM ('state is corrupted', 'a guard is missing', 'the function is callable', 'value diverges') without a concrete consequence is NOT a body finding: cap it at Informational and route it to the Quality Observations megasection."

### 10.2.5 PoC execution mandate with harm assertion (Phase 5)
- "A PoC that is written but never executed provides ZERO mechanical evidence. Only executed tests produce ground truth."
- Tags: `[POC-PASS]` (compiled, executed, assertions passed — "mechanical proof"; "the only tag that supports CONFIRMED as ground truth"); `[POC-FAIL]` ("defaults to the attack not working — to override, demonstrate the failure is test setup error, not a defense"); `[CODE-TRACE]` ("caps at CONTESTED unless the trace is complete with real constants"); `[MEDUSA-PASS]` (same weight as POC-PASS).
- **Impact Premise Verification (HARD GATE)**: "identify the finding's claimed HARM in one sentence… The PoC MUST assert the HARM directly. A PoC that only proves a function can be called, a state can be reached, or a path exists is NOT a `[POC-PASS]` — it is a mechanism test, not a harm test." Mechanism-test examples (insufficient): "'startLiquidation succeeds while market is active' — proves a function call, not user loss". Harm-test examples (required): "'claimant receives 15% less than their pro-rata share after attack sequence'". "If you cannot construct a harm assertion, the finding is `[CODE-TRACE]` at best."
- **PoC Testability Ledger** (mandatory per verifier output): PoC Required / PoC Class ∈ unit|property|integration|structural / Attempted / skip reason ∈ {NO_BUILD_ENVIRONMENT, EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS, DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL, PURE_SPEC_OR_DOCS_ONLY, STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION, N/A}. For `unit`/`property` rows a local executable attempt is mandatory whenever a build harness exists; `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` is NOT an allowed skip for them; cargo languages require in-crate PoC placement (`src/poc_{id}.rs` via `#[cfg(test)] mod`).
- **Fork PoC mandate**: any Medium+ finding whose harm is an external-integration fund drain/misrouting "is NOT `structural`… the effective PoC class is floored to `integration`". Single-chain external dependency at a known address → mandate `forge test --match-test test_{ID} --fork-url {RPC_URL} --fork-block-number {PINNED} -vvv`, "Assert the CLAIMED HARM directly (funds drained / misrouted / over-paid)". Passing fork run = `[PROD-FORK]` (proof-grade). Cross-chain relay legs → structured skip. No fork RPC → `[UNPROVEN-EXTERNAL]` stamp: "The finding STAYS IN THE BODY at its **proven-mechanism severity**… must NOT promote it ABOVE that severity on the assumed worst-case external behavior (and never demotes it below)."
- Fix generation only for `[POC-PASS]` findings: minimal diff-style fix; "If the fix is non-trivial (architectural change…): write `**Fix**: Architectural change required — {1-sentence}`"; re-run PoC with fix to verify it no longer triggers (`Verified: YES/NO`).
### 10.2.6 Pre-PoC verification protocol (EVM verification-protocol skill)
Three mandatory questions before writing any test: (1) exact bug ("[Variable] is [read/written] at [location] but should be… because [specific reason]" — NOT "state is wrong"); (2) observable difference ("Before operation: [var] = [expected]. After operation: [var] = [actual]. Expected: [what it should be]"); (3) exact assertion (`assertEq(actualValue, expectedValue, "description")` / `assertNotEq(before, after, "value changed when it shouldn't")` / `assertGt(error, threshold, "error exceeds acceptable threshold")`). "If you cannot answer all three → ASK FOR CLARIFICATION." Test types: STANDARD (single tx, before/after), TEMPORAL (loop N intervals advancing time; "Assert error exceeds threshold (e.g., >1% = 100 BPS)"), BOUNDARY (edge value array: minimum unit, break points, edges, normal, maximum). Verifier Step 0 is RAG validation: `assess_hypothesis_strength` (reconsider if <0.5), `get_similar_findings`, `search_solodit_live`; record historical precedent YES/NO and pattern confidence.

### 10.2.7 4-axis confidence scoring (Phase 4)
`composite = Evidence×0.25 + Consensus×0.25 + Analysis_Quality×0.3 + RAG_Match×0.2`.
- Evidence = best evidence tag score (table in 10.2.1).
- Consensus = "(agents that flagged same root cause) / (agents whose domain covers this location). If only 1 agent's domain covers the location → Consensus = 1.0 if that agent found it. **Specialized agent bonus**: +0.2 when finding discovered by an agent instantiated from a Required skill template (capped at 1.0)."
- Analysis Quality: depth agents scored on count of Depth Evidence tags (0→0.1, 1→0.4, 2→0.7, 3+→1.0); others on step execution (✓ / total applicable).
- RAG Match = validate_hypothesis result / 10; 0.3 floor if RAG tools failed.
Routing: ≥0.7 CONFIDENT (stop); 0.4–0.7 UNCERTAIN (spawn targeted depth agent); <0.4 LOW (depth + force production verification + RAG deep search). Budget priority: `spawn_priority = (1 - composite) × severity_weight` (Critical 4 / High 3 / Medium 2 / Low 1 / Info 0.5). Re-scoring rules: monotonic confidence; "Score increase requires at least one NEW evidence tag"; "No self-referential scoring: The scoring agent scores based on evidence artifacts in the scratchpad files, not on the depth agent's self-reported confidence."

### 10.2.8 Depth evidence tags (evidence of *analysis*, not just claims)
`[BOUNDARY:X=val]` (substituted concrete boundary value, e.g. `windowSize=0 → weight=MAX_INT`); `[VARIATION:param A→B]` (e.g. `decimals 18→6 → price inflated 1e12x`); `[TRACE:path→outcome]` (traced to terminal state, e.g. `withdraw(maxUint)→revert at L120 "insufficient"`); `[CROSS-DOMAIN-DEP: {domain}]` (assumption outside own domain); `[EXTERNAL-ASSUMPTION]` (worst-realistic-condition severity per R10 — **citation-gated**: must carry `[EXT-CITED: <dep>, source=<url>, fetched=<date>]` or a `NEEDS_DEPENDENCY_RESEARCH` escalation, else scored `[CODE-TRACE]`-equivalent and "cannot support a VERIFIED/proof-grade disposition"); `[REGRESS:symptom→cause]`; `[PERTURBATION:operator]`.

### 10.2.9 Verification-status legend (report binding)
`VERIFIED` = CONFIRMED verdict AND proof-grade evidence (`[POC-PASS]`/`[MEDUSA-PASS]`/`[PROD-*]`); `CONFIRMED` = verdict CONFIRMED but only `[CODE-TRACE]` ("A real confirmed finding — NOT `UNVERIFIED`"); `CONTESTED` = disputed; `UNVERIFIED` = refuted/false-positive/none. Sort strength VERIFIED > CONFIRMED > CONTESTED > UNVERIFIED.

### 10.2.10 Severity matrix + downgrade modifiers (report template)
Impact × Likelihood matrix (High impact+High likelihood=Critical; Medium impact any likelihood=High/Medium/Medium; etc.). Modifiers applied after lookup: on-chain-only exploit → −1 tier (but NOT when impact crosses on/off-chain boundary, e.g. corrupted events breaking indexers); view-function-only → cap Medium; "Attack path requires fully-trusted actor (per project's stated trust assumptions) to act maliciously → −1 tier (floor: Informational). This applies ONLY to `FULLY_TRUSTED` actors (governance multisig, DAO, timelock). Semi-trusted actors (admin, operator, keeper, oracle) are NOT downgraded here." Root-cause consolidation: same root cause (same *fix*) → one finding, highest severity, sub-impacts listed. **Body vs Appendix floor**: pure-quality findings (missing events, no-shown-loss zero-address checks, one-step ownership, defense-in-depth, signature binding hardening with no shown exploit…) → Appendix C; "ANY real security consequence keeps it in the body AT ANY SEVERITY"; "**Recall-safe default: when in doubt, BODY.** Burying a real finding in the appendix is the unacceptable error; an extra body finding is cheap." Report ID hygiene: clean severity-prefixed IDs only (C-01, H-01…), "NO internal pipeline IDs appear anywhere in the client-facing report."


### 10.2.11 Chain analysis (enabler matching) — Phase 4c
For each PARTIAL/REFUTED finding: extract missing precondition + type; for STATE-type, match on the **specific state variable name** against all findings writing that variable; search ALL CONFIRMED/PARTIAL findings for matching postconditions across severities — "Also search the low-confidence candidate enablers". "If either constituent is an unverified candidate enabler, mark the chain LOW-CONFIDENCE… Never report such a chain as confirmed without verification." Cross-domain dependency scan consumes `[CROSS-DOMAIN-DEP]` tags from depth agents. This operationalizes the "composition candidates" that other methodologies only mention.

### 10.2.12 Orchestration hard rules (V2)
Python driver owns runtime policy (phase scheduling, artifact gating, checkpoint/resume, rate-limit pause); prompts own methodology. Critical rules worth stealing: NEVER-CUT agent list with explicit halt-on-exhaustion ("Do NOT silently degrade to Core-equivalent coverage while claiming Thorough mode"); Phase 5 completion assertion before any report agent ("'All PoCs passed so skeptic is unnecessary' is NOT a valid skip reason — Skeptic-Judge enforces severity calibration, not just exploit verification"); compaction survival (re-read checkpoint file after context compaction, never trust in-context memory); version-mismatch check at startup.

## 10.3 Contradictions
- **Fuzz evidence**: `[MEDUSA-PASS]` = proof-grade (1.0, same as POC-PASS) vs digger's "fuzz evidence ≠ confirmed vulnerability" ceiling vs trident's "fuzzing mostly yields no violations". Plamen's position is defensible only for *counterexample found* (a failed invariant with a concrete replay), which is exactly what digger caps below confirmed — an unresolved epistemic split worth arbitrating explicitly.
- **Mock handling**: plamen permits mocks for CONFIRMED evidence at 0.2 weight; foundry-poc-mainnet-fork bans mocks from causal chains entirely. Plamen's asymmetric rule is the principled middle.
- **Semi-trusted actors**: plamen explicitly does NOT downgrade semi-trusted (admin/operator/keeper/oracle); The-Judge caps severity on "trusted role abuse" (which plausibly includes these); contract-auditor's prerequisite tier 4 (protocol role) caps at Low. The same admin-only finding lands at Low (web3-skills), downgraded (plamen), capped (The-Judge), or killed (claude-bug-bounty) — the single most divergent judgment across the cluster.
- **Orchestration cost**: plamen's phase-per-subprocess isolation (fresh context per phase) contradicts finite-monkey's error-accumulation minimization (fewer actions) in spirit, though isolation also *bounds* drift. Tension between chain-length minimization and context-freshness guarantees.

## 10.4 Gaps
- Heavy Claude Code dependency and multi-agent budget (~dozens of agents in Thorough); no unified severity math for L1/consensus findings beyond the shared matrix; PoC skip enums can be abused if not audited; the `[UNPROVEN-EXTERNAL]` concept is powerful but only partially enforced (R10).

## 10.5 Classification
**Core methodology** (full pipeline) with the strongest **validation mechanism + judge mechanism** sub-systems (Phase 5 PoC mandates, mock-rejection asymmetry, 4-axis confidence, skeptic-judge, severity matrix). plamen is the natural backbone onto which the other repos' gates attach.

---

# 11. web3-skills — contract-auditor / client-auditor / exploit-investigator

## 11.1 Contribution
Three sub-skills from the same maintainers: **contract-auditor** (lead-auditor orchestration with a rigorous finding validation protocol for Solidity), **client-auditor** (chain-client/Substrate audit with 3-lens judging, confidence scoring, and mechanical severity override rules), **exploit-investigator** (post-incident triage of a tx hash into a validated, on-chain-evidence-only report via an analyst↔validator debate loop).

## 11.2 Most valuable techniques

### 11.2.1 contract-auditor — severity-tiered validation requirements
"Validation rigor scales with severity":
| Severity | Validation required |
|---|---|
| Critical/High | Full protocol: 3 Hard Gates + 6D Scoring + PoC Quantification |
| Medium | Gates 1–3 required; profit may be indirect; 6D recommended |
| Low | Gate 1 (concrete path) required; unlikely preconditions OK; no profit requirement |
| Design Advisory | Code location + documented design intent + non-obvious consequence; "Does NOT pass through Three Hard Gates — this is not a bug" |
| Informational | Specific code location + explanation; "Must be a **true valid observation** — not a linter warning" |

### 11.2.2 Filter 0 — Design Intent Gate (runs at ALL severities, before anything else)
1. Read design signals (NatSpec, comments, naming, parameter names, architecture). 2. **Clearly intentional** → "**DROP** with evidence citation: quote the specific NatSpec, comment, or naming convention that confirms intent. Exception: if the intentional behavior has non-obvious consequences… report as **Design Advisory**." 3. **Ambiguous** → proceed, "flag the ambiguity for adversarial review. Note what evidence you looked for and didn't find." 4. **Clearly unintentional** → proceed.

### 11.2.3 Filter 1 — Three Hard Gates (Critical/High: fail ANY = discard)
- **Gate 1 Concrete Attack Path**: "Trace the complete path: `caller → function → state change → impact`. Every step must be specified with exact function names and parameters. 'It could be exploited' without a concrete path = **discard**."
- **Gate 2 Attacker Reachability**: "The entry point is accessible and EVERY modifier/require on the path is satisfiable by the attacker. Verify each `onlyRole`, `whenNotPaused`, `nonReentrant`, and custom modifier. If any modifier blocks the attacker = **discard**." Plus the **Payability sub-check**: "VERIFY the function is actually marked `payable` — read the function signature. For delegatecall chains: verify the ENTRY POINT is payable… If the function is NOT payable, `msg.value` is always 0 = **discard**."
- **Gate 3 No Existing Safeguard**: "No `require`/`revert`/guard in the codebase already blocks this exact path."

### 11.2.4 Filter 2 — Six-Dimension Adversarial Scoring (mechanical verdict)
Score D1 Guards / D2 Reentrancy / D3 Access control / D4 Design intent / D5 Economic feasibility / D6 Dry run, each −3 (strong protection) to +1 (confirmed vulnerable). "Mechanical verdict from sum: ≤ −6 → **DISCARD**; −5 to −1 → **DOWNGRADE** one tier; 0 to +2 → **EMIT** at assessed severity; ≥ +3 → **ESCALATE** one tier." Skipped for Low/Informational ("their value is in flagging the code concern, not proving exploitability").

### 11.2.6 client-auditor — 3-lens evaluation (anchors, not gates)
Lens 1 Concrete Execution Path (file:line sequence, no dead code, attacker input specified); Lens 2 External Reachability (P2P/RPC/consensus entry, no admin creds, network path specified); Lens 3 No Sufficient Existing Guard (each claimed mitigation checked against code; "The finding survives layered defense analysis"). Calibration: "A finding weak on one lens is not automatically a false positive — report it with explicit caveats and reduced confidence… A finding weak on all three is usually noise."

### 11.2.7 client-auditor — confidence scoring (100 − deductions, stacking)
−30 admin/operator; −40 hardened trusted-party key compromise; −25 >33% Byzantine validators; −80 ≥ consensus quorum; −20 non-default config; −15 feature-gated/not deployed; −15 self-contained impact; −10 existing partial mitigation; −10 sustained >1hr attack; −40 input rejected by deserialization; −50 no current exploit path (latent only). Severity bands: Critical ≥80 (chain-wide/financial); High ≥70; Medium 40–69; Low 20–39; Informational <20.

### 11.2.8 client-auditor — 8 mechanical severity override rules
1. Never promote above the impact ceiling. 2. Documented design trade-off → cap Informational. 3. Chain-wide impact keeps Medium even at low confidence. 4. Admin-only → cap Medium (unless the admin interface itself is the finding). 5. Hardened-key compromise → cap Low, with a **system-wide exception** to Medium ("The test is whether the blast radius is system-wide or node-local"). 6. No current exploit path → cap Low; future-code-change-only → Informational. 7. Self-recovering resource exhaustion → cap Medium. 8. Quorum-required exploit → cap Informational ("the attacker already has full control of the protocol… Any secondary bug… is subsumed by the catastrophic primary compromise. Report as a defense-in-depth observation only."). "They are calibrated against historical audit experience and should not be deviated from without explicit reasoning."

### 11.2.9 exploit-investigator — analyst↔validator debate loop with on-chain truth
Pipeline: parse tx → Planner (`analysis_plan.json`, `trace_callTracer.json` REQUIRED) → Data Collector (manifest + sources; decompiler on demand, max 5 concurrent) → manifest check → **Analyst-Validator debate (max 2 rounds)**: Analyst writes `report.md`; Validator runs (Stage 1) Logical Challenger — internal consistency against fetched source only; (Stage 2) On-Chain Verifier — "cross-check every claim against on-chain data via RPC"; issues classified **CRITICAL** (root cause wrong / contract misidentified / mechanism fundamentally incorrect → blocks pipeline) vs **WARNING** (presentation errors → auto-fix, non-blocking). Stage gating: PASS / PASS_WITH_WARNINGS / FAIL. Round 2 = re-validation against the Analyst's `debate_log.json`; CRITICAL at round 2 → FAIL. **PoC generation only on explicit user request** ("Never auto-run PoC generation"). Public-report hygiene gate: no internal file paths, no trace indices, on-chain facts only; style-check failures are blocking and don't consume debate rounds. Outputs are structured enough "for downstream local automation to decide whether the incident is a real exploit."

### 11.2.10 Dedup rules (client-auditor)
"1. Same function, same bug: Merge… highest severity. 2. Same pattern, different entry points: Keep separate but note the shared root cause; fix should address root cause. 3. Cascading effects: If Finding A enables Finding B, report both… If fixing A eliminates B, note that B is contingent."

## 11.3 Contradictions
- **Arithmetic conflict**: contract-auditor's 6D sum thresholds (≤−6 discard) vs client-auditor's 100-minus-deductions bands — two incommensurable scoring systems in the same skill family; a finding can EMIT under one and cap at Low under the other.
- **Admin ceilings diverge again**: contract-auditor tier 4 → Low; client-auditor rule 4 → Medium; plamen → −1 tier (fully-trusted only); The-Judge → cap; claude-bug-bounty → kill. Five different answers.
- **"By design"**: contract-auditor Filter 0 DROPs intentional behavior (unless Design Advisory); The-Judge DT-* *downgrades* it; plamen R13 demands a terminal user-facing consequence be documented before REFUTED closure on "by design". Drop vs downgrade vs document differ materially for report contents.
- **Latent findings**: client-auditor caps no-current-path at Low/Informational; The-Judge's US-3/OS-3 marks such findings INVALID; plamen's appendix policy would keep "latent/none-at-present hazards" in Appendix C. A latent bug is Low, Invalid, or Appendix depending on the judge.
- **Evidence citation**: exploit-investigator forbids any non-on-chain citation in public incident reports — stricter than every auditor skill, which cite source code freely (contexts differ: incident reports vs audit reports).

## 11.4 Gaps
- contract-auditor: default mode has no falsifier (DEEP only); PoC quantification is required for Critical/High but its mechanics are thinner than plamen's (no harm-assertion hard gate, no skip ledger).
- client-auditor: Substrate/chain-client specific lenses; confidence deductions are hand-calibrated with no published data.
- exploit-investigator: EVM-centric chain list; requires Alchemy key; report quality depends on fetched source completeness.

## 11.5 Classification
**contract-auditor = core methodology** (orchestration + finding validation protocol). **client-auditor = specialized sub-skill** (chain clients) whose judging.md is the best severity-calibration reference in the cluster. **exploit-investigator = specialized sub-skill** (incident validation) whose debate loop and on-chain verifier are the reference model for post-mortem validation.

---

### 11.2.5 Prerequisite Tier Table (severity ceilings)
"The tier of the HARDEST prerequisite in the chain… caps the maximum severity": Tier 0 none → Critical; 1 victim must sign/approve → High; 2 specific market condition → High; 3 non-standard token behavior → Medium; 4 attacker needs protocol role → Low; 5 admin key compromise → Low (report only if mechanism concrete). "**Trust model override**: When a trust model is provided… the trust model's severity ceilings take precedence over generic tier ceilings."

# 12. Synthesis — unified classification, contradictions ledger, pipeline proposal

## 12.1 Unified skill classification (recommended placement)

| Repo | Classification | Role in a unified system |
|---|---|---|
| plamen | **core methodology** + validation mechanism + judge mechanism | Backbone pipeline (scoping → breadth → depth → PoC → skeptic-judge → report) |
| web3-skills/contract-auditor | **core methodology** | Alternative backbone for lighter engagements; supplies Filter 0/Three Gates/6D/prerequisite tiers |
| web3-skills/client-auditor | **specialized sub-skill** (chain clients) | judging.md severity override rules = shared severity-calibration reference |
| web3-skills/exploit-investigator | **specialized sub-skill** (incident validation) | Post-incident triage; debate loop + on-chain verifier |
| foundry-poc-mainnet-fork | **validation mechanism** (PoC construction sub-skill) | Executor behind every "PoC required" verdict; anti-anchoring + no-shortcut rules |
| trident-fuzz-skill | **validation mechanism** (invariant/fuzz sub-skill, Solana) | Fuzz module; invariant sensitivity/durability + sufficiency checklist generalize to Echidna/Medusa |
| The-Judge | **judge mechanism** (core) | Final verdict layer for third-party/AI findings; invalidation library = shared reference |
| finite-monkey-engine | **judge mechanism + validation mechanism** | Validator prompt schema; error-accumulation law; hypothesis-cloud model; *anti-patterns* documented |
| K.I.T | **validation mechanism** (known-issue detection/dedup) | Prior-register gate; llm_contract spec |
| claudit | **tool integration** (reference search) | Solodit MCP for RAG sweeps / novelty checks |
| digger | **tool integration + validation mechanism** | Deterministic engine-truth validator (`validate_assistant_output`), typed enums, confidence ceilings |
| claude-bug-bounty | **validation mechanism** (fast triage gates) | Submission-side 7-question gate / kill checklist; web3 hunt checklist |
| scoping-bee | **core methodology** (scoping/recon phase) | Pre-audit scope, threat ladder, complexity rubric, effort model |

## 12.2 The five unresolved cross-repo contradictions (arbitration needed)

1. **Induction vs neutrality.** finite-monkey deliberately induces hallucination for recall ("there IS a bug — find it"), then validates; plamen/forward-branch/digger use neutral prompts that may legitimately return zero findings. *Arbitration suggestion:* keep detection neutral (precision) and let the judge do adversarial work — The-Judge's architecture already reconciles the two; the induced prompt should only ever be a bounded recall-boosting sweep whose output passes through identical validation gates.

2. **Weight of fuzz evidence.** plamen: `[MEDUSA-PASS]` = proof-grade (1.0, equals `[POC-PASS]`). digger: fuzz artifact evidence caps at `invariant_failed`/`failure_replayed`, "not a confirmed vulnerability". trident: fuzzing mostly yields no violations and is for confidence/regression. *Arbitration suggestion:* adopt digger's split — a *replayed counterexample with a seed/sequence* is proof-grade (plamen's position), a *maturity signal* is not; encode the replay requirement into the tag itself (`[MEDUSA-PASS]` must carry seed + sequence, or demote to `[CODE-TRACE]`).

3. **Admin/role findings (5 different dispositions).** claude-bug-bounty: KILL (submission context). The-Judge: cap severity. plamen: −1 tier for fully-trusted only, semi-trusted NOT downgraded. contract-auditor: tier 4 role → Low; tier 5 key → Low. client-auditor: admin cap Medium, key compromise cap Low w/ system-wide exception. *Arbitration suggestion:* separate "should this ship" from "what severity": always ship role-gated findings (plamen body rule + recall-safe default), and normalize severity with client-auditor's override rules (most granular), applied only when a trust model exists (contract-auditor's trust-model override).

4. **Mock evidence.** plamen: mocks can confirm (weight 0.2) but never refute (automatic CONTESTED override). foundry-poc: mocks banned from causal chains. claude-bug-bounty: `deal()`/prank freely used. *Arbitration:* adopt plamen's asymmetry globally; adopt foundry-poc's real-contract mandate for any PoC claimed as proof; treat `deal`-style PoCs as `[MOCK]`-grade at most.

5. **Latent/no-current-path findings.** The-Judge: INVALID. client-auditor: Low, or Informational if only future changes activate it. plamen: Appendix C ("latent/none-at-present hazards"). *Arbitration:* never INVALID (false negatives cost more); client-auditor's Low/Informational split is correct; plamen's Appendix placement loses the finding from the report body and should be overridden to Low.

## 12.3 A unified validation pipeline (composing the repos)

```
FINDING IN
  │
  ├─ [scoping-bee] Scope/context: attack surface match, trust model, complexity tier
  ├─ [K.I.T + claudit]  Known-issue gate: known / possibly-known / new (root-cause+surface+impact match)
  │
  ├─ [contract-auditor] Filter 0 design-intent → drop-with-citation | Design Advisory | proceed
  ├─ [contract-auditor] Three Hard Gates (path, reachability+payability, no safeguard) → discard on fail
  ├─ [claude-bug-bounty] 7-question submission gate (if bounty context) → kill/downgrade
  │
  ├─ [The-Judge] Invalidation library sweep (selector + generic checkers)
  │   + issue-specific generator (beyond-catalog adversarial reasons)
  │   + neutral judge on disagreement → VALID / INVALID / DOWNGRADED
  ├─ [finite-monkey] ValidationCodexPrompt schema
  │   (intended_design|false_positive|vulnerability|vuln_high_cost|vuln_low_impact|not_sure)
  │
  ├─ PoC required for Medium+?
  │     ├─ YES: [foundry-poc-mainnet-fork] real-contract causal-chain PoC (no deal/prank bypass)
  │     │        [plamen Phase 5] harm-assertion hard gate + testability ledger + fork mandate
  │     ├─ property/invariant class: [trident-fuzz-skill] invariant harness (sensitivity-tested)
  │     └─ NO (structural): [plamen] ledger skip reason required; [CODE-TRACE] cap
  │
  ├─ [digger] validate_assistant_output — mechanical claim-vs-engine check (typed enums)
  │
  └─ [plamen report-template + client-auditor judging] severity matrix → override rules →
      body-vs-appendix floor → VERIFIED/CONFIRMED/CONTESTED/UNVERIFIED stamp
```

## 12.4 Consolidated gate library (what to lift verbatim into a shared skill)

**Kill/downgrade gates** (cheap first): claude-bug-bounty Q1/Q4/Q6/Q7 + Fast Kill Checklist; contract-auditor Filter 0 + Three Gates + payability sub-check; The-Judge invalidation library (UP/CP/DT/EG/US/SH/DI/TI/SC/IM/AM/OS codes).

**Evidence rules**: plamen tag hierarchy ([PROD-ONCHAIN] 1.0 … [EXT-UNV] 0.1); mock-rejection asymmetry; harm-assertion hard gate; `[UNPROVEN-EXTERNAL]` stamp; digger's confidence ceilings on parsed artifacts.

**Verdict schema**: `verdict ∈ {CONFIRMED, PARTIAL, REFUTED, CONTESTED}` (plamen) + `status ∈ {intended_design, false_positive, vulnerability, vuln_high_cost, vuln_low_impact, not_sure}` (finite-monkey) + `known/possibly-known/new` (K.I.T) + typed severity/confidence/stage enums (digger). A single finding record should carry all four dimensions.

**Severity**: plamen impact×likelihood matrix + client-auditor 8 override rules + contract-auditor prerequisite tiers (trust-model-gated) + The-Judge Step 5 recalibration (severity from verified path, not claimed).

**PoC**: foundry-poc reading-order/anti-anchoring/classification + plamen testability ledger/skip enums + trident sensitivity tests.

**Batch/runtime**: The-Judge parallel waves + inter-issue notes; plamen checkpoint/resume + NEVER-CUT + compaction survival; K.I.T fail-closed staged contracts; finite-monkey error-accumulation budget (<10 LLM actions per finding).

## 12.5 Remaining gaps (opportunities)

- No repo combines archive-fork PoC + invariant fuzz + adversarial judge in one flow (plamen is closest; its fuzz is EVM-Medusa only, its Solana fuzz absent).
- Cross-chain relay PoCs have no tooling anywhere (plamen structured-skip only).
- Severity interop: no mapping layer between digger enums, The-Judge verdicts, plamen statuses, and K.I.T known-ness.
- No published benchmark data for any judge's false-positive/false-negative rates (The-Judge claims results without artifacts).
- Solidity-version-aware priors (finite-monkey's ≥0.8.0 overflow rule) need a registry, not hard-coding.
