# Digger — Evidence-Gated Security Triage Engine: Methodology Extraction Report

**Repo:** `/home/nishan/ultimate-web3-security/sources/digger` (digger-determsec/digger, Rust workspace, Apache-2.0)
**Analyst note on provenance:** the request described this as "a property-based fuzzing/verification tool 'Digger' by ChainSecurity/others." The repo actually analyzed is **digger-determsec's Digger** — an "Evidence-gated security analysis for smart contracts and the agents that touch them" (`README.md`). It does *not* execute property-based fuzzing; its fuzzing surface ("Track K") is limited to *static fuzz-maturity scanning* and *fuzz artifact ingestion* (Foundry/Echidna/Medusa/Crucible failure logs), with an explicitly capped confidence ceiling. This discrepancy is itself a notable methodological finding (see §3). All quotes below are verbatim from the repo with file paths.

---

## 1. Contribution Summary (what the repo does)

Digger is a deterministic, evidence-gated smart-contract security *triage* engine (EVM + Solana, Rust) built around one architectural idea: the engine produces **ranked hypotheses with mandatory evidence chains, never confirmed vulnerabilities**, and LLM/agent outputs are quarantined behind deterministic validation gates. Its pipeline is `contract / address / repo / calldata → detectors → evidence → ranked hypotheses → triage (JSON) → render-report → Markdown` (`docs/WHY-DIGGER.md`). Core artifacts are schema-versioned JSON packets (`digger.hypothesis.v1`, `digger.proof_task.v1`, `digger.claim_verification.v1`, `digger.evidence_package.v1`, `digger.report_draft.v1`) that chain a finding lifecycle: a hypothesis lists `evidence_required` and `disproof_conditions`; a proof task constrains `allowed_tools`, `forbidden_actions`, `validation_gates`, and `stop_conditions`; a claim verification compares `evidence_satisfied` vs `evidence_missing` and returns `insufficient_evidence` until every gate is met; an evidence package links the chain and states its limitations. Every artifact hard-codes `"is_finding": false`. Around this core sit: an MCP server with four read-only agent tools including a guardrail validator (`validate_assistant_output`) that rejects severity/confidence/stage promotion; an egress consent gate (`--no-network`, `--allow-egress`) so network use is opt-in; a deterministic Markdown report generator with curated per-rule prose and real precedent citations; an intent verifier that decodes calldata/transactions into Safe/Suspicious/Dangerous; a benchmark + "eval gate" CI that enforces per-detector recall floors and zero false positives on a held-out FP corpus; and a ground-truth corpus of real exploits (Sentiment, Conic Finance, dForce, Sturdy, Midas…) with positive/negative pairs and citation metadata. The project's positioning: "AI can suspect. Digger proves." (`docs/product/LLM-ASSISTED-BETA-BOUNDARY.md`) — a triage tool and evidence layer for agents, explicitly "not a replacement for a professional audit" (`README.md`).

---

## 2. Most Valuable Techniques and Judging Gates (verbatim-worthy)

### Gate 1 — Hypotheses, not verdicts (the master epistemic gate)
`README.md`:
> "Digger surfaces *hypotheses*, not \"guaranteed vulnerabilities.\" Every finding is tied to concrete evidence — an exact line, call path, or storage slot — and cites real, verifiable precedents. When it doesn't know, it says so."

`docs/WHY-DIGGER.md` states the five pillars:
> "1. **Hypotheses, not verdicts.** Findings are ranked hypotheses with explicit confidence — never \"confirmed vulnerabilities.\" 2. **Evidence-gated.** No claim ships without a concrete evidence chain (line / call path / storage slot). No evidence, no claim. 3. **Deterministic core.** Same input → same output, every run. 4. **Real precedents only.** Similar known incidents are cited with verifiable links (Parity, Poly Network, Wormhole, …) — never invented. 5. **Honest about limits.** Known gaps are documented in plain sight."

### Gate 2 — The `is_finding: false` invariant, enforced everywhere
Every sample packet and every schema test pins `is_finding` to `false`:
- `sample-output/evm-hypothesis.json`: `"status": "proposed"`, `"confidence": {"level": "low", "reason": "hypothesis only; no proof task executed"}`, `"is_finding": false`.
- `sample-output/evm-verification.json`: `"status": "insufficient_evidence"`, `"status_reason": "1 surfaces matched but 3 required evidence items remain missing for claimed components"`, `"is_finding": false`.
- `docs/CONNECT-YOUR-AGENT.md`: "**is_finding: false.** All outputs maintain this invariant."
- In Rust, this is a *validation contract*, not a convention: `crates/digger-agent-proof-task/src/validation.rs` has `IsFindingTrue => write!(f, "is_finding must be false")` and `validate_proof_task` rejects any task with `is_finding == true`, alongside `EmptyTaskId`, `MissingRequiredEvidence`, `MissingValidationGates`, `MissingStopConditions` etc.

### Gate 3 — The evidence-gated pipeline as an explicit state machine
`docs/product/LLM-ASSISTED-BETA-BOUNDARY.md`:
> "Model output must flow through the Plan 3 evidence stack:
> ```
> Hypothesis → ProofTask → EvidenceRun → VerificationDecision
> ```
> No model interface may include `decide_valid_finding`. Model outputs are untrusted evidence inputs, never truth."

The proof-task schema (`sample-output/evm-proof-task.json`) is a reusable template for any agentic audit workflow:
```json
"allowed_tools": ["source_review"],
"forbidden_actions": ["no_execution", "no_network"],
"expected_outputs": ["evidence_record", "validation_result"],
"validation_gates": ["evidence_refs_populated"],
"stop_conditions": ["evidence_refs_empty_after_max_attempts"]
```
This "task that names what evidence closes it, what tools may not be used, and when to stop" is directly portable to any AI-audit skill.

### Gate 4 — Typed labels instead of strings (severity/confidence/stage enums)
`skills/digger/SKILL.md`:
> "Findings carry typed severity (info/low/medium/high/critical), confidence (experimental/graduated), and stage (shadow/advisory/armed) enums — never strings."

`skills/digger/README.md`:
> "Findings are structurally typed — severity is an enum (info/low/medium/high/critical), confidence is (experimental/graduated), stage is (shadow/advisory/armed). The engine never up-labels. The guardrail validator returns a deterministic failure report for assistant claims that promote severity, confidence, or stage beyond engine truth."

### Gate 5 — The `validate_assistant_output` guardrail with machine-checkable violation codes
The four MCP tools are all `readOnlyHint: true`: `list_findings`, `get_evidence`, `get_explanation_context`, `validate_assistant_output` (`docs/CONNECT-YOUR-AGENT.md`). The smoke test `skills/digger/scripts/quickstart.sh` proves the gate behavior end-to-end by submitting a "true" claim and a "lie" claim:
```bash
TRUE_CLAIM="...\"severity\":\"$SEVERITY\",\"confidence\":\"$CONFIDENCE\"..."
LIE_CLAIM="...\"severity\":\"critical\",\"confidence\":\"$CONFIDENCE\"... \"claim_text\":\"promoted\""
```
and asserting:
```python
assert report['pass']==False, f'promoted severity must fail, got: {report}'
codes = {v['code'] for v in report['violations']}
assert 'SEVERITY_UPGRADED' in codes, f'missing SEVERITY_UPGRADED, got: {codes}'
```
This is the strongest anti-hallucination pattern in the repo: the *human/agent* claim is validated against engine truth with a deterministic pass/fail plus typed violation codes — a template for any "judge" component.

### Gate 6 — Forbidden LLM capabilities list (architecture-level policy)
`docs/product/LLM-ASSISTED-BETA-BOUNDARY.md`:
> "These must never exist in any future model interface: `decide_valid_finding` — models must never decide what constitutes a valid finding; Create final findings; Create EvidenceRun objects; Create proof packages; Make severity decisions as truth; Confirm vulnerabilities; Bypass evidence gates; Mutate deterministic facts; Override validation failures."

Allowed model capabilities are equally explicit: "Summarize evidence; Propose hypotheses; Rank attack surfaces; Explain evidence; Draft report text; Suggest invariants; Suggest fuzz/proof tasks." The provider abstraction has a `none` mode: "`DIGGER_MODEL_PROVIDER=none` is a first-class mode. The deterministic engine runs without any model. AI is an optional accelerator, never a requirement."

### Gate 7 — Claim-verification with satisfied/missing/next-steps (the judge output shape)
`sample-output/evm-verification.json` demonstrates the decision protocol that any verification stage should emit:
```json
"evidence_satisfied": ["Surface 'deposit' found (provenance=engine, engine_derived=false)"],
"evidence_missing": [
  "Surface 'deposit': Authority/modifier enforcement evidence needs review for function `deposit` at Safe.sol:L32-L35",
  "Surface 'deposit': Evidence for engine hypothesis 'AuthorityBypassCandidate' requires verification against IR/graph",
  "Surface 'deposit': Evidence for engine hypothesis 'StateCorruptionCandidate' requires verification against IR/graph"
],
"validation_failures": [],
"required_next_steps": [
  "Address missing evidence items cited above",
  "Provide additional source references or proof tasks"
]
```
Key discipline: **one missing evidence item blocks the whole claim** (no partial credit), and the output must name *what would close the gap*.

### Gate 8 — Triage packet structure (hypothesis → missing evidence → proof task chains with IDs)
`sample-output/evm-triage.json` shows the triage vocabulary that scopes the audit:
- `attack_surface_summary`: `{"surfaces_scanned": 13, "privileged_functions": 11, "state_mutation_sites": 9, "external_call_sites": 2, "heuristic_fallback_count": 0, "engine_files_ok": 1}`
- `candidate_hypotheses[]` with `hypothesis_id` (e.g. `engine-HYP-AUTH-approve`), `provenance: "engine"`, `confidence: "engine-verified"`, `severity: "Critical"`, `status: "requires_investigation"`, `evidence_requirements: ["graph evidence", "IR verification"]`
- `missing_evidence[]` with `evidence_id` (e.g. `me-cei-5`), `category` (e.g. `reentrancy_cei`), `source_ref: "Safe.sol:L58-L63"`
- `privileged_operations[]` with `reason: "[engine] authority_required, external_call"`
- `proof_tasks[]` with `task_id: "pt-engine-HYP-AUTH-approve"`, `priority`, `evidence_type`, `hypothesis_ref`, `status: "pending"`
- `limitations[]` with stable `limitation_id`s (e.g. `lim-source-triage`, `lim-static-triage`, `lim-fuzz-not-requested`)

### Gate 9 — Deterministic report generator: curated prose only, PoC scaffolds marked as drafts
`docs/REPORT-GENERATOR.md`:
> "All prose is curated per-rule content or real engine evidence — never fabricated. Every sentence is either (a) written once per detector class, or (b) from the actual finding data. PoC scaffolds are explicitly marked as unverified drafts. Precedent citations link to real, verifiable incident reports."

Nine fixed sections per finding: Title / Summary / Why it matters / Location & Code / Evidence path / Severity & Confidence / Similar known issues / How to fix / PoC scaffold. CLI:
```bash
digger render-report --from triage.json --top 5 --min-confidence confirmed
digger render-report --from examples/sample-report/sample_packet.json -o report.md
```

### Gate 10 — CI integration and fail-on gates
`.github/workflows/digger.yml` (the dogfood workflow):
```yaml
- name: Run Digger CI scan
  run: |
    cargo run --bin digger -- ci --format sarif > digger-results.sarif
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  continue-on-error: true
- name: Post PR comment
  if: github.event_name == 'pull_request'
  run: |
    cargo run --bin digger -- ci --format pr-comment > digger-comment.md
    gh pr comment ${{ github.event.pull_request.number }} --body-file digger-comment.md
- name: Fail on high severity
  if: github.event_name == 'pull_request'
  run: cargo run --bin digger -- ci --fail-on high
```
Notable: SARIF upload is `continue-on-error: true` (informational), while `--fail-on high` is a hard PR gate — a clean separation between signal and blocking policy.

### Gate 11 — Eval gate: per-detector recall floors + zero-FP held-out corpus, enforced in CI
`crates/digger-benchmark/src/gate.rs` — the FP/recall enforcement logic:
```rust
if m.fp > 0 {
    held_out_fp.push(format!("{}: {} FP on held-out", m.detector, m.fp));
    // ... precision_violations.push(...)
}
if m.recall < m.recall_floor { /* recall violation */ }
if m.fp > 0 { /* precision violation on labeled corpus */ }
let gate_passed = held_out_fp.is_empty() && precision_violations.is_empty() && recall_violations.is_empty();
```
The report carries `held_out_fp_violations`, `precision_violations`, `recall_violations`, `gate_passed`. Every `DetectorMeasurement` has `precision_floor` and `recall_floor` (e.g. `precision_floor: 1.0` for op-layer detectors, `recall_floor: 0.4` for graduated detectors — see `crates/digger-benchmark/tests/gate_bites.rs`). CI runs it as a hard gate:
```yaml
- name: Eval gate unit tests
  run: cargo test -p digger-benchmark --test gate_bites --test gate_e2e
- name: digger validate (production gate path)
  run: cargo run --bin digger -- validate
```
(`.github/workflows/ci.yml`, job `eval-gate`, commented "Eval Gate (FP + recall enforcement)").

### Gate 12 — Held-out FP corpus: the anti-overfitting quarantine
`corpus/held-out-fp/README.md` contains exactly one rule, all-caps:
> "DO NOT import these fixtures from detector logic or tuning code."

The corpus encodes "looks-vulnerable-but-safe" patterns, e.g. `evm-benign-bounded-oracle` (an oracle *with* a deviation bound — a detector that naively flags "oracle" would FP), `solana-benign-pda-validated` ("Proper PDA seeds + bump validation"), and a set of op-layer `handler.ts` negatives (verified feeds, allowlisted routes, fail-closed breakers, adjusted failover). Held-out FPs must never be used for tuning — only for the gate — which is the standard ML train/test discipline applied to security detectors.

### Gate 13 — Ground-truth corpus with labeled expected outputs (positive/negative pairs per class)
`corpus/composability/read-only-reentrancy/README.md` pairs 5 real exploits (with dates, losses, citations) against 5 safe patterns, each negative case explaining the *guard*:
> | safe-view-reentrancy-check | ExternalCall->StateRead | View checks reentrancy lock (OZ #4422) | Reverts if called during reentrancy window |
> | safe-callback-no-state-read | ExternalCall (no StateRead after) | CEI pattern | State reads before external call |
> | safe-benign-call-then-read | ExternalCall->StateRead | Read is benign (logging/display) | Not security-critical |

Each case ships a `meta.json` with machine-checkable expectations, e.g. `corpus/composability/read-only-reentrancy/conic-finance-2023/meta.json`:
```json
"expected_findings": ["ReadOnlyReentrancy"],
"expected_path_types": ["external_call_before_state_read", "stale_pool_balance_during_callback"],
"expected_hypotheses": ["ReadonlyReentrancyCandidate"],
"known_limitations": ["Vulnerable pattern: Curve pool ETH balance read AFTER callback — stale during reentrancy"]
```
The negative twin (`safe-benign-call-then-read/meta.json`) encodes the FP lesson directly:
> "NEGATIVE: ExternalCall followed by StateRead, but the read value is NOT used for any security-critical decision (just logging). This is the #1 FP source for naive ExternalCall->StateRead detectors. Detector must NOT flag."

### Gate 14 — Security-criticality filter: not every ExternalCall→StateRead is a bug
This is the reachability-vs-exploitability distinction made concrete. `corpus/composability/read-only-reentrancy/README.md`:
> "safe-benign-call-then-read + safe-view-only-callback: test the security-criticality filter. Both have ExternalCall->StateRead but reads are not price/balance used for valuation."
and for `safe-view-only-callback`: "StateRead is compound-assignment artifact, not price/balance for collateral." The detector must distinguish *pattern presence* from *pattern that gates a security decision* — the same gate the FP corpus enforces at the CI level.

### Gate 15 — Fuzz maturity scan: signals, vacuity warnings, and the confidence ceiling
`crates/digger-fuzz-maturity/src/scanner.rs` header:
> "Per ADR-0038: harness presence is not evidence of a bug, clean fuzz runs are not proof of absence, and no replayable failure means no high-confidence fuzz finding."

The scan scores ten signals (Foundry invariant tests +20, Echidna +20, Medusa +20, handler contracts, target config +10, meaningful assertions +15, setup/state +10, CI fuzz jobs +5, corpus/reproducer +5, property hints +5) and emits `vacuity_warnings` like:
- `category: "empty_invariant"` — "Invariant/fuzz functions found but appear to lack meaningful assertions."
- `category: "all_empty"` — "All invariant/fuzz candidates appear empty or trivial." (score −20)
- `category: "config_no_test"` — "Fuzz config files found but no matching invariant/test files."
Crucially, `confidence_ceiling` is pinned: "the ceiling must never exceed harness/config_present in K.1" (`scanner.rs` test) — the scan can at most say *harness/config present*, never `campaign_ran_clean`, `invariant_failed`, or `failure_replayed`. Detection heuristics are documented, e.g. `is_fuzz_invariant_file` matches `invariant`, `fuzz`, `echidna`, `stdinvariant`, `echidna_`; configs: `echidna.yaml`, `medusa.json`, `foundry.toml`.

### Gate 16 — Fuzz evidence ingestion: two-level confidence ceiling (artifact-backed only)
`skills/digger/SKILL.md`:
> "Parses existing Foundry, Echidna, or Medusa invariant/property failure output into a structured evidence report. Confidence ceiling is `invariant_failed` (no replay command) or `failure_replayed` (replay command present). This is evidence for triage, not a confirmed vulnerability."

`crates/digger-fuzz-maturity/src/foundry.rs` implements it exactly:
```rust
let has_failure = lc.contains("failing test") || lc.contains("test failure")
    || lc.contains("invariant violation") || lc.contains("counterexample") || /* ... */;
let replay_command = extract_after(content, &["forge test --match-test", "replay"]);
let confidence_ceiling = if replay_command.is_some() { "failure_replayed" } else { "invariant_failed" };
let raw_excerpt = if content.len() > 2048 { format!("{}...", &content[..2048]) } else { /* ... */ };
```
And `is_vulnerability_finding: false` is schema-pinned by test. Replay-command presence is the discriminator between "a fuzzer once failed" and "a failure you can reproduce" — the tool refuses to emit the higher tier without an artifact-backed replay. Same logic in `medusa.rs` (`"medusa replay"`, `"replay command:"`) and `crucible.rs` (`replay_command` field of `.meta.json`).

### Gate 17 — Egress consent gate (network safety for scanners)
`docs/EGRESS-GATE.md`:
> "Before any HTTP request, Digger calls `authorize_global(url, purpose)`. The gate checks: offline mode → trust store → interactive prompt (TTY) → deny."
Flags: `--no-network` ("Hard offline mode — zero network calls, fail-closed"), `--allow-egress <host>`, `--assume-yes`. The trust store persists "only `SCHEME://HOST` pairs, never full URLs or API keys"; "File mode 0600 on Unix." Every network site (`explorer.rs`, `solana_rpc.rs`, `txwatch`, `scan_live.rs`, `fetcher.rs`) goes through the gate — a concrete, auditable pattern for any tool that wants agent-safe network behavior.

### Gate 18 — Intent verifier: "know before you sign" with risk tiers and non-finding status
`docs/INTENT-VERIFIER.md`: decodes raw calldata (`--calldata 0x...`), JSON txs (`--tx`), EIP-712 (`--eip712`), Solana txs (`--sol-tx`) into Safe / Suspicious / Dangerous tiers:
> | Suspicious | Unknown selector, or known dangerous function without matching expected target |
> | Dangerous | Known high-risk function (e.g., upgrade, mint, pause) with no guardrails |
and always "`is_finding: false` — this is a decoded explanation, not a security finding." `--to`/`--expected` flags detect UI-vs-reality address mismatch. This is a pre-signing user-protection gate, orthogonal to auditing.

### Gate 19 — Agent-trust contract and reproducible-evidence checklist
`docs/agent-integration.md` — "Trust Model" table:
> | Engine truth | Digger output and validation gates are authoritative over LLM prose. |
> | Evidence preservation | LLM summaries must preserve raw evidence. Never summarize away errors or omit fields. |
> | Validation failures | If Digger validation fails, agents must not override it with reasoning. |
> | Reproducibility | Evidence should be reproducible, versioned, and tied to command output. |
> | Version identity | Tag, binary version, release notes, and artifacts must align. Agents should record `digger --version` with every evidence bundle. |

Agent workflow pattern: Inspect → Form hypothesis → Run Digger command → Capture raw evidence → Validate JSON against schema → Summarize *with* evidence references → "**Stop** on any validation failure — do not override with reasoning." An evidence-bundle directory convention (`raw/`, `normalized/`, `reports/`, manifest with exact commands + exit codes) is proposed.

### Gate 20 — Quality gates and benchmark gate for the tool itself
`scripts/quality-gates.bat`: five gates — build, zero-warning `cargo check`, all tests, benchmark "ALL CASES PASSED", and `digger ingest validate` (ingestion integrity). `digger validate` reports "Version check / Schema version check / Phase 3 freeze integrity check / Frozen modules list / Frozen schemas list / Frozen hypothesis/compound/assumption/inversion/verification types" (`docs/CLI_REFERENCE.md`) — i.e., a self-check that the tool's own schema contracts are intact, which is what makes the whole evidence-gating chain trustworthy.

### Supporting gate — Severity handling
There is **no impact/likelihood rubric** in this repo. Severity is a typed enum assigned by the engine's ranking step ("Rank by severity and confidence", `docs/architecture/ARCHITECTURE.md`) and models are forbidden to "Make severity decisions as truth" (`docs/product/LLM-ASSISTED-BETA-BOUNDARY.md`). Sample values in `examples/sample-report/sample_packet.json`: `severity: "critical" | "high" | "medium"` with `confidence: "confirmed" | "high" | "experimental"` and `rule_id: "authority_bypass" | "state_corruption" | "price_manipulation"`. The triage packet goes further and labels *candidate hypotheses* `severity: "Critical"` with `status: "requires_investigation"` — severity is attached to hypotheses to drive prioritization, with the `is_finding: false` flag carrying the epistemic caveat.

---

## 3. Contradictions with Other Methodologies

1. **Not the ChainSecurity property-based fuzzing Digger.** The premise under which this repo is often filed ("Digger = property-based fuzzing by ChainSecurity") does not hold here. `skills/digger/SKILL.md` is explicit: "These are static-repo CLI commands — they do NOT run fuzzers and do NOT emit vulnerability findings." Digger *ingests* fuzzer output but never executes Foundry/Echidna/Medusa/Crucible; harness generation and Crucible execution are "future work." Any methodology that treats Digger as a fuzzer will mis-scope it.

2. **Fuzzing philosophy inversion.** Mainstream fuzzing-first methodologies treat "invariant harness exists and passes" as (weak) positive evidence of safety and treat a fuzz failure as a near-finding. Digger's ADR-0038 stance inverts both: "harness presence is not evidence of a bug, **clean fuzz runs are not proof of absence**, and **no replayable failure means no high-confidence fuzz finding**" (`crates/digger-fuzz-maturity/src/scanner.rs`). Confidence ceilings are deliberately crippled: `harness/config_present` (maturity scan) and `invariant_failed` / `failure_replayed` (evidence ingestion) — never `failure_minimized`, never `poc_test_generated`. Methodologies that let an invariant failure auto-escalate to a finding contradict this directly.

3. **Scanner-by-design produces "no findings".** Most scanner methodologies output findings; Digger's outputs are universally `"is_finding": false` and its verification output is `insufficient_evidence` until a human/agent closes named gaps. A triage report whose most prominent section is `missing_evidence` (22 items in `evm-report-draft.json`) contradicts the expectation of "here are your bugs" tooling — it produces *work plans*, not results.

4. **Determinism and no-LLM core vs LLM-centric audit skills.** "No model output enters this pipeline. The LLM-assisted layer … is a separate, quarantined interface" (`docs/architecture/ARCHITECTURE.md`) and "The engine decides verdicts; the assistant never does" (`skills/digger/SKILL.md`). This contradicts LLM-native audit methodologies where the model is the reasoning engine and deterministic tools are optional plugins. Digger inverts the roles: the model is an untrusted analyst whose every claim passes a deterministic validator.

5. **Heuristics are admitted, not hidden — but only as a disclosed fallback.** Some methodologies refuse anything short of AST/dataflow truth; Digger's triage discloses: "Source triage uses conservative text heuristics. No AST parsing, no compilation, no execution" (`sample-output/evm-hypothesis.json` `disproof_conditions`), with heuristic fallback counted and surfaced (`"heuristic_fallback_count": 0`, `"provenance": "repo_intelligence"`, `"heuristic": true`). The contradiction with strict static-analysis purism is resolved by *labeling provenance per surface* rather than by abstaining.

6. **Severity attached to unconfirmed hypotheses.** Because the triage packet assigns `"severity": "Critical"` to `AuthorityBypassCandidate` entries that are simultaneously `"is_finding": false`, Digger parts ways with methodologies that forbid severity labels until a bug is confirmed. Here severity is a triage-prioritization label on a hypothesis, decoupled from truth via the status/confidence/is_finding fields — worth adapting carefully, since consumers who ignore `is_finding` will misread it.

7. **Read-only agent posture vs execution-oriented agents.** Digger's MCP surface is strictly read-only (`readOnlyHint: true` on all four tools, "Digger never executes anything", `docs/CONNECT-YOUR-AGENT.md`), contradicting agent skills whose workflow includes `forge test`, fuzzing runs, or PoC execution as first-class steps. Digger's boundary table states: "No autonomous exploit generation. No fuzzer execution. No LLM-as-proof." (`docs/agent-integration.md`, "Safety Boundaries").

8. **Precision absolutism.** The eval gate treats *any* FP on held-out or labeled corpora as a violation (`precision_floor: 1.0` for several detectors, including experimental op-layer ones). Most scanner methodologies trade precision for recall or tune thresholds per deployment; Digger instead caps what it claims (experimental vs graduated) rather than shipping low-precision detectors — recall is allowed to be low (honest "2/4 validated classes"), precision is not.

---

## 4. Gaps (What It Does NOT Do)

- **No fuzzer execution, harness generation, or property-authoring language.** There is no `digger test` DSL, no invariant-syntax documentation beyond *ingestion parsers* for other tools' artifacts; "Crucible execution and harness generation remain future work" (`skills/digger/SKILL.md`). A user seeking property-based testing gets only maturity assessment and evidence ingestion.
- **No cross-contract/cross-function analysis.** "Single-contract scope (no cross-contract dataflow yet)" (`README.md`); no compilation or type checking (`docs/LIMITATIONS.md`). The read-only-reentrancy corpus explicitly caps recall: "sturdy-finance: cross-contract callback … Structural FN. Max recall ceiling = 4/5 = 80%."
- **No runtime verification stack in beta.** `predicate_states` is "intentionally empty until a production predicate registry exists" (`skills/digger/SKILL.md`); the LLM firewall, data-boundary policy, model-call audit, report verifier, and model evaluation harness are "Schema / Policy Baseline (Defined, Not Yet Runtime-Enforced)" (`docs/product/LLM-ASSISTED-BETA-BOUNDARY.md`). The `digger-verification` crate *generates* `VerificationProperty` predicates (`Always`, `Eventually`, `Before`, `Implies`, `Not`, `And`, `Or` over `Condition`s like `HasAuthority`, `ReadBeforeWrite`, `ExternalBetweenReadWrite`) from AuthorityGraph/StateTransition/ResourceLifecycle/CEI models (`crates/digger-verification/src/generator.rs`), but this generator is not wired into the shipped triage workflow in the sample outputs.
- **No PoC execution or confirmation.** PoC scaffolds are "explicitly marked as unverified drafts" (`docs/REPORT-GENERATOR.md`); the evidence package states "Evidence package is a planning-only artifact. No runtime packaging implemented" (`sample-output/evm-evidence-package.json`).
- **No severity rubric** (no impact/likelihood matrix, no CVSS-like rules) — only enum assignment by the ranking engine; models may not decide severity as truth.
- **No MCP/HTTP exposure for fuzz reports** ("All tool parsers are CLI-only for now; they are not exposed through the MCP server").
- **Platform/class gaps:** Solana detection is "constraint-absence based (3 axes only: ownership, authority-binding, signing)"; EVM modifier detection "may miss complex multi-line patterns"; flash-loan governance detector "unverified on real targets"; file:line spans "remain partial for op-layer and Solana classes"; op-layer detectors are syntactic-proxy heuristics ("A handler that passes all four checks may still have runtime vulnerabilities; a handler that fails one may be safe in context not visible to the parser").
- **No recall guarantees.** "Recall varies by detector and class … This is triage, not a full audit"; the tool "gives no guarantee that a contract is safe" (`README.md`).
- **No multi-tenant MCP isolation** ("This skill runs a single-tenant local server. There is no multi-tenant isolation between scan requests" — container-per-user required).
- **Windows trust-store limitation:** the 0600 chmod on `~/.digger/trust.json` is Unix-only; Windows inherits default ACLs (`docs/LIMITATIONS.md`).

---

## 5. Classification in a Unified Security Skill Taxonomy

Digger spans several categories simultaneously:

1. **Core methodology** — the evidence-gated pipeline (`Hypothesis → ProofTask → EvidenceRun → VerificationDecision`), hypotheses-not-verdicts doctrine, `is_finding: false` invariant, and the agent-trust model are a general *method* for running AI-assisted audits, not a tool-specific trick. This is the primary classification.
2. **Validation mechanism** — `validate_assistant_output` with typed violation codes (`SEVERITY_UPGRADED` etc.), proof-task validation contracts (`is_finding must be false`, non-empty gates), and schema-contract tests are a reusable anti-hallucination/anti-promotion layer.
3. **Judge mechanism** — the claim-verification output shape (`evidence_satisfied` / `evidence_missing` / `required_next_steps`, all-or-nothing `insufficient_evidence`), the eval gate (recall floors, precision floors, held-out-FP zero tolerance), and the fuzz-evidence confidence-ceiling ladder (`invariant_failed` → `failure_replayed`) form a deterministic judging framework with explicit stop conditions.
4. **Specialized sub-skill** — fuzzing evidence ingestion (Foundry/Echidna/Medusa/Crucible artifact parsing with replay-command discrimination), fuzz-maturity scanning (signal scoring + vacuity warnings), and transaction intent verification are distinct sub-skills within the broader audit workflow.
5. **Reference material** — the ground-truth corpus (real exploits with citations, losses, `expected_findings`/`expected_path_types`/`expected_hypotheses`, paired safe/unsafe cases, held-out FP quarantine) and the precedent-linked report sections are curated knowledge assets usable independently of the tool.
6. **Tool integration** — CLI (`audit-triage`, `hypothesis`, `render-report`, `fuzz-maturity`, `fuzz-evidence`, `benchmark`, `validate`, `ci`), MCP stdio server, REST API with hashed-key auth, SARIF upload + PR comment + `--fail-on` CI workflow, and agent SDKs (Python/Rust/TypeScript clients).

**Preservation priority for a unified skill:** Gates 2, 3, 5, 7, 11, 12, 15, 16 (the `is_finding: false` invariant, the evidence-stack state machine, the validator-with-violation-codes, the all-or-nothing verification shape, the recall/FP eval gate, the held-out corpus quarantine, and the fuzz confidence-ceiling ladders) are the pieces that generalize most cleanly beyond this codebase and should be lifted verbatim or near-verbatim into any agentic security-audit skill.
