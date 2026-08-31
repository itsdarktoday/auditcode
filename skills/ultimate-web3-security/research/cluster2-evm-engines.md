# Cluster 2: EVM / DLT Audit Engines — Deep Extraction Report

**Scope:** krait, hound, dlt-auditor, grimoire, nemesis-auditor, open-kritt, SolidityGuard, ZeroSkills, AI, defi-builder-skills (under `/home/nishan/ultimate-web3-security/sources/`).
**Focus axes:** adversarial auditing, evidence-gating, hypothesis generation, multi-agent orchestration, co-auditor patterns, threat modeling, attack-surface enumeration, finding quality over quantity.
**Method:** read SKILL.md / README / METHODOLOGY / agent prompts / reference files per repo; all quotes verbatim.

---

# 1. Krait (ZealynxSecurity) — `krait/`

## Contribution summary

The most complete, empirically-validated Solidity audit engine in the cluster, encoded as Claude Code skills + a TypeScript CLI critic. A 4-phase pipeline (preflight → recon → detection with 3 recall passes → state analysis → critic kill-gates → reviewer second-opinion → reporter), backed by 101 heuristics (43 core + 58 extended), 15 deep-dive module files, 7 protocol primers, 8 kill gates + Impact Premise, 10 FP patterns, and a 6-field "methodology audit trail" per finding. Measured **100% precision / 0 FPs / 15.2% recall across 50 blind Code4rena shadow audits**; a self-improving loop ("score → root-cause every miss → update methodology → re-test") produced all 101 heuristics "from real missed findings — not from theory." Ships a standalone `krait-poc` skill with the strongest falsification protocol in the cluster, a shadow-audit regression harness that gates methodology changes, and an 845+-check assessment framework.

## Most valuable techniques (with quotes)

1. **8 automatic kill gates (A–H) run first on every candidate, before any analysis.**
   > "This gate runs FIRST. Any finding matching ANY of these 8 categories is IMMEDIATELY killed. No exploit trace is attempted. No further analysis. No exceptions. No 'but in this case...'. KILL IT. These 8 categories account for 95%+ of all false positives across 40 shadow audits and have NEVER produced a true positive. They are unconditional kills."
   Gates: A generic best practice, B theoretical/not-exploitable (with **token-context check**), C intentional design (with **fork-origin check**), D speculative, E admin trust, F dust, G out-of-context, H publicly known.

2. **Impact Premise gate — harm, not mechanism (v8.2).** Before any trace, the candidate must carry a one-sentence statement of **WHO loses WHAT**:
   > "Mechanism statements — INSUFFICIENT. These describe machinery, not damage: '`startLiquidation` succeeds while the market is active' — proves a call is possible, not that anyone loses… Harm statements — REQUIRED: 'claimants receive 15% less than their pro-rata share after the attack sequence'."
   Killed class `MECHANISM-ONLY` is explicitly flagged as "the reviewer's highest-priority revival class, because a missing description is cheap to fix."

3. **Devil's-advocate falsification with "innocent until proven guilty" burden inversion:**
   > "The burden of proof is on the FINDING, not on the code… There is NO 'likely true' or 'insufficient evidence' — either you proved it or you didn't. **When in doubt, KILL it.** A missed real bug is unfortunate. A false positive destroys credibility."
   Plus the cross-feed revival question: "Before marking anything as FALSE POSITIVE, also ask: 'Does ANY other finding in this audit enable the missing precondition?'"


4. **Gate H precision requirement — match on mechanism, not topic:**
   > "Match on MECHANISM, not TOPIC. 'SOFT_RESTRICTED bypass via open market' ≠ 'SOFT_RESTRICTED bypass via withdraw()'. Two bugs in same area with different exploit paths are different bugs."

5. **DoS severity exception to gates A/B/D/F:**
   > "If DoS permanently/repeatedly bricks a CORE lifecycle function… → Medium minimum, survives A/B/D/F. 25% of missed findings were DoS bugs incorrectly killed."

6. **Detector-side PRE-FILTER (mirror of the gates) to stop wasted effort:**
   > "These 8 categories have produced ZERO true positives across 35 shadow audits. Do NOT waste time generating candidates… **For ANY token-behavior finding (FoT, rebasing, missing return, hooks), you MUST name the SPECIFIC token from THIS protocol's actual deployment. 'If a FoT token is used' = kill.**"

7. **Rescan pass (B4) — exclusion-list second pass against attention saturation:**
   > "A first pass fixates on the most prominent bug in each file and under-reads everything around it… A file with no findings is UNDER-ANALYZED, not clean — 13% of all historically missed findings were in areas an earlier pass explicitly marked safe."
   Includes a **hard exit rule** (skip if pass 1 found nothing above Info) and duplicate policy: "Same area, different exploit path = **not** a duplicate."

8. **Per-contract pass (B3) — one agent per inheritance cluster against attention dilution:**
   > "Cluster size cap: ~1500 LOC… Maximum 8 clusters… Maximum 5 findings per cluster — prioritise by severity. This is a depth pass, not a volume pass."
   Mandatory file-coverage checkpoint: "Any `Opened: NO` → open and analyze it before returning. 28% of historically missed findings were in files the agent never opened." Recall-safe exclusion rule: "A bare 'already known' with no location and no referent is a suppressed bug, not an exclusion… **When in doubt, emit.**"

9. **Methodology audit trail (6 fields) on every finding** — `stepExecution` (which lenses/gates ran), `rulesApplied` (R8 cached-parameter, R10 worst-state severity, R11 unsolicited tokens, R12 exhaustive enabler enumeration, R15 flash-loan preconditions, R16 oracle integrity), `depthEvidence` tags `[BOUNDARY:X=val] [VARIATION:A→B] [TRACE:path→outcome]`, `missingPrecondition/preconditionType` (STATE/ACCESS/TIMING/EXTERNAL/BALANCE), `postconditionsCreated/whoBenefits`. Purpose: "show your work to downstream agents and so future chain analysis can match preconditions to postconditions."

10. **Reviewer phase — a second opinion agent that re-examines the critic's kills** (catches over-filtering):
    > "The Critic asks: 'Can I DISPROVE this?' The Reviewer asks: 'Did the gate DISMISS this too quickly?'"
    Gate-specific re-examination priorities (C highest, E high, B medium), revival output labeled "Worth Manual Review", plus: "Cluster analysis matters. Individual kills might be correct, but clusters of kills in the same area can reveal systemic issues."

11. **Severity calibration rule:**
    > "Do NOT downgrade to MEDIUM just because the exploit requires multiple steps or specific ordering… **Severity under-rating was the #1 calibration error in shadow audits.** When in doubt between H and M, rate HIGH — the Critic will downgrade if warranted."

12. **Root-cause consolidation (A7)** — merge N locations of one root cause into one finding (≤6 locations, same fix pattern/severity tier/class), with the inverse caution: "A duplicate finding is cosmetic. A dropped true positive is a missed vulnerability. When in doubt, keep them separate."


13. **krait-poc falsification gate — the strongest PoC discipline in the cluster:**
    > "A passing exploit is a *hypothesis*, not a result, until it survives an attempt to falsify it… **Defect-mutation**: Change the defective line(s) themselves to their correct form… Re-run the exact same exploit test, unchanged. Exploit still passes → `[POC-UNPINNED]`… Exploit now fails → the test is pinned to a real defect."
    Two orthogonal controls (defect-mutation = pin; fix-efficacy = remediation quality), a negative/baseline control, a recursion trap rule ("Do not iterate a candidate fix against a single exploit test. That is theater again"), and `FIX-INSUFFICIENT` treated as "a finding, not a failure." Evidence ladder: `[POC-PASS]` / `[POC-PASS · FIX-INSUFFICIENT]` / `[POC-UNPINNED]` / `[POC-FAIL]` / `[CODE-TRACE]`.

14. **PoC batch triage lanes + recall-safe demotion policy:**
    > "A passing PoC promotes a finding. A failing PoC demotes it. Inability to PoC does neither… Never write a STRUCTURAL or BLOCKED finding as 'invalid,' 'false positive,' or 'unverified.'"
    Lanes: TESTABLE / STRUCTURAL (TRUSTED_ACTOR, OFF_CHAIN_HARM, CROSS_CHAIN_DESTINATION, LIVENESS_DENIAL…) / BLOCKED (env reasons) / NO-HARM. "A report that dropped every un-PoC-able finding would delete real governance, off-chain, and cross-chain issues — the exact bugs manual auditors are paid to find."

15. **Empirical gating of the methodology itself:**
    > "The gate blocks on any new false positive and on a recall drop worse than 2 pp."
    Unmeasured claims are quarantined: "Do not quote these numbers as Krait's performance. They are recorded here so the eventual regression has something to compare against." Kill-gate parity between skill and CLI is enforced in code (`enforceGateContract`) with a build-failing parity test.

16. **AST/extractor ground truth:**
    > "Do NOT override AST facts with your own inference. If the AST says function X has modifier Y, it has modifier Y."
    Slither output is demoted to "ADDITIONAL SIGNAL, not as auto-reported findings."

## Contradictions

- **Internal:** the critic's Core Rule ("There is NO 'likely true' or 'insufficient evidence' — either you proved it or you didn't") directly contradicts its own verdict assignment (TRUE POSITIVE / LIKELY TRUE / DOWNGRADE / FALSE POSITIVE / INSUFFICIENT EVIDENCE) and the reporter's instruction to include LIKELY TRUE findings.
- **Internal:** the critic says "Never add new findings" then immediately: "Exception: cross-feed iteration can generate new candidates for immediate verification."
- **Internal:** the pipeline simultaneously claims zero-FP gates are correct ("This is correct for the main report") and that they over-kill ("aggressive gates have a cost: over-killing real findings") — resolved only by the separate reviewer pass, which is opt-in (`/krait-review`).
- **Internal:** SKILL.md front matter claims "Tested at 100% precision across 50 blind shadow audits" while METHODOLOGY.md itself warns v8.1/v8.2 numbers are unvalidated — the honesty is there but the headline number is stale.
- **Cross-repo:** Gate E (admin trust = kill, except missing timelock) conflicts with grimoire's finding-review guidance and defi-builder-skills' emergency-mechanism analysis (pause traps user funds), which treat admin/governance capability as reportable material.
- **Cross-repo:** Gate H (kill acknowledged issues) is the **opposite** of DLT Auditor's protocol-mapper note: "repository docs, README notes, public issue lists, or 'out of scope' comments are useful metadata, but they do not by themselves kill a candidate… require current code-level evidence that the exact mechanism is fixed."
- **Cross-repo:** krait's severity ladder and hard gates are stricter than every other engine here (open-kritt's CONFIRMED/LIKELY/FALSE_POSITIVE post-scripts, hound's confidence scores, nemesis' verification methods).

## Gaps

- Recall is the weak axis (15.2% v8; 54.1% in an n=3 pilot) — the entire design optimizes precision first.
- Solidity-only (no Rust/Move), unlike nemesis/dlt-auditor.
- PoC execution is **opt-in and separate** (`/krait-poc`) rather than a pipeline phase; findings without PoC cap at `[CODE-TRACE]`.
- Grounding depends on forge/AST extraction; the regex fallback silently weakens the "compiler-verified facts" claim.
- No cost budget or per-finding economics; no multi-model ensemble; critic/reviewer only *filter*, they never hunt (the one thing hound/ZeroSkills add).

---

# 2. Hound (muellerberndt) — `hound/`

## Contribution summary

A language-agnostic, Python autonomous auditor built around **agent-designed knowledge graphs**, a **scout/strategist model split**, a **belief & hypothesis system with confidence scores**, and two planning regimes (Coverage/Sweep then Saliency/Intuition). Long-horizon: hypotheses persist across sessions (`proposed/investigating/confirmed/rejected/resolved`), a QA `finalize` command re-reviews high-confidence hypotheses with full source context, and a chatbot UI allows live human steering of a running audit.

## Most valuable techniques

1. **Strict scout/strategist role separation with a context-preparation contract:**
   > "The deep think model (guidance) is a separate, expensive reasoning engine… It can ONLY analyze the context you prepare - if you don't load it, it can't analyze it!… Scout (you) gathers code and facts… NEVER speculate about vulnerabilities and do NOT adjudicate them yourself."
   > "NEVER call deep_think without loading substantial code context first (5-10+ nodes minimum)."

2. **Coverage → Saliency phase transition (explore-then-exploit planning):**
   > "SWEEP MODE STRATEGY: … Output ASPECT items only — one per component… INTUITION MODE STRATEGY: … PRIORITIZE MONETARY IMPACT above all else… Look for CONTRADICTIONS between assumptions and observations… Output primarily SUSPICION items."
   Switch rule: "If coverage < 90%, use Coverage mode. Otherwise, use Intuition mode."

3. **Every plan item must carry WHY NOW + EXIT CRITERIA** (bounded investigation scope): "For each investigation, include WHY NOW and EXIT CRITERIA in 'reasoning'."

4. **Observation vs hypothesis separation:**
   > "Graph observations/assumptions: Facts about HOW the system works… Hypotheses: Suspected SECURITY ISSUES… Never mix these — security concerns always go in hypotheses, not in graph updates."

5. **Human steering mid-audit** — a queue consumed exactly once: "Steering is queued at `<project>/.hound/steering.jsonl` and consumed exactly once when applied. Broad, global instructions may preempt the current investigation and trigger immediate replanning."

6. **Hypothesis lifecycle + confidence threshold review (`finalize`)** — reviews "hypotheses above the confidence threshold with full source code context. Confirms or rejects each hypothesis with reasoning."

7. **LLM-assisted hypothesis dedup with a cheap pre-filter** (require "meaningful, non-generic node overlap to consider duplicates") before paying for a semantic comparison.

8. **Plan ledger** for cross-session transparency: normalized plan frames, sessions/models seen — "It does NOT block repeated frames — different sessions/models can analyze the same items intentionally."

9. **PoC generation from hypothesis annotations** — windows file content around annotated lines (±20 lines) instead of dumping whole files.

10. **Coverage tracking** as explicit audit progress ("Graph nodes visited vs total, Code cards analyzed vs total").

## Contradictions

- The scout is forbidden from forming hypotheses even when it spots them; if the strategist is only invoked after 5–10 nodes are loaded, many leads die on the way — the prompt itself acknowledges "incomplete context = incomplete analysis."
- Coverage mode caps breadth ("Maximum 1 item per component") which conflicts with its own "wide sweep to visit every component"; the 90% mode-switch threshold is a heuristic with no supporting measurement in-repo.
- Confidence scores replace krait-style kill gates — but confidence is self-assigned by the same model that found the bug; no independent falsification except the optional `finalize` pass.
- README promises "cumulative audits" while `reset-hypotheses` (with backup) suggests the store is regularly discarded.

## Gaps

No kill gates / FP taxonomy / harm-assertion rule; no exploit trace requirement (PoC is an optional command); no severity calibration; no token-context checks; no evidence tags or audit trail; no published precision/recall in-repo (paper referenced externally); smart-contract-oriented prompts despite "language-agnostic" branding.

## Classification

**Reference material for multi-agent orchestration** (scout/strategist split, coverage/saliency phases, exit criteria, belief system, steering) and **tool integration** (knowledge-graph exploration). Not a methodology body on its own.

- State analysis (Phase 2) is optional (`/krait-quick` skips it), diluting the pipeline's own structural claims.

## Classification

**Core methodology** — the strongest backbone candidate for a unified security skill (pipeline + kill gates + Impact Premise + audit trail). `krait-poc` → **validation mechanism**; `shadow-audits/` + `scripts/shadow-regress.ts` → **judge mechanism / regression harness**; `checklist/` (845+ checks, severity guide) → **reference material**.


---

# 3. DLT Auditor — `dlt-auditor/`

## Contribution summary

A runtime orchestrator for **trained, per-venue prompt packs** ("designs") with **blind-suite integrity** and a historical DLT vulnerability corpus. No single monolithic pipeline: each design was trained against a specific competition (monad-c4, fuel-core-attackathon, nibiru-c4…) by an outer loop — "The AI runs the design, compares the output with confirmed findings, studies what it missed, and refines the prompts. That loop repeats until the prompt pack can identify all or almost all of the confirmed findings." Phases: `mapper → corpus → scans → canonicalize → validations → aggregate → final`. The phase prompts themselves are the densest attack-surface-enumeration and validation-gating text in the cluster.

## Most valuable techniques

1. **Specialized design packs over one universal pipeline:**
   > "There is no single audit pipeline that tries to fit every project. Instead, the auditor has multiple prompt-pack designs, and each one is tuned toward a different project family, competition style, or vulnerability class… each design still runs in isolation so its output does not influence the others."

2. **Blind-isolation rules for benchmark integrity:**
   > "Keep blind audit execution separated from answer-key material. During blind audit execution, do not read known findings, benchmark ground truth, scorecards, miss analyses, result records, leaderboards, refinement plans, audit-output snapshots, candidate result archives, prior round folders, sibling suite outputs, or stable `designs/*/runs/**` output."
   (Also the inverse: `optimal` tier selection must inspect design files but "Do not inspect generated runs or answer-key material while selecting.")

3. **`00_protocol_mapper.md` — protocol-centered threat map before any hunting.** 24+ mapping tasks including: trust boundaries; externally/peer/operator/governance-reachable entrypoints; signed/proof-bearing artifacts "and what they are supposed to bind"; attestation binding (height, round, block hash, domain, signer set, voting-power snapshot); a **field-binding matrix** for ZK circuits; **"authoritative sources of truth … Distinguish them from caches, local config, watch channels, mirrors, and derived summaries"**; "For each major security decision, note the observation layer and the enforcement layer."

4. **`02_validation_and_impact.md` — skeptic-first validation with a 60+ item missing-property taxonomy:**
   > "You must act like a skeptic first and only conclude 'confirmed' if the code supports it… Trace the exact data flow and control flow from untrusted input to the sensitive sink. Identify every check that exists on the path. Explain which property is missing or incomplete."
   Then 19 issue-class discrimination rules, e.g.: "If the issue involves validator votes… distinguish syntactic validity, signature validity, validator-set membership, voting-power quorum, freshness, and domain separation. **Do not treat one property as proof of the others.**"
   Impact-claim discipline: "Preserve the invariant and hunt lesson, but avoid impact claims such as consensus break, theft, forged state, or remote DoS unless the code path and attacker capability are demonstrated."
   Mandatory output schema: Verdict / Missing property / Entry point / Sensitive sink / Required attacker capabilities / Compensating controls / Impact / Severity / Why justified / **What test or proof would strengthen confidence**.

5. **`01_base_hunter.md` — ingress-to-sink equivalence matrices:**
   > "For transaction, block, message, and proof admission, build an ingress-to-sink matrix… Mark which paths are trusted bypasses and which are untrusted. Every untrusted path should run the same policy, resource, context, and protocol-message checks before the object reaches the shared sink."
   Plus "any-success collapse" ("Treat `any success`, `or`, first-success, nil-on-one-branch, and generic-error collapse as suspicious when the checks validate different required properties"), and a hard quality cap: "Produce at most 5 candidate findings, ranked by likelihood."

6. **Corpus patterns as hypotheses, never evidence:**
   > "Corpus matches are used as search patterns and hypotheses for the current target. They are not evidence by themselves. A finding still needs target-code reachability, attacker capability, a missing property, and concrete impact."

7. **Docs/known-issues do NOT pre-kill candidates:**
   > "repository docs, README notes, public issue lists, or 'out of scope' comments are useful metadata, but they do not by themselves kill a candidate. Record them in context, then require current code-level evidence that the exact mechanism is fixed before a later scan suppresses it."

8. **Resume semantics preserving work under worker limits** ("Preserve generated suites when worker limits or external interruptions occur. Resume instead of recreating").

## Contradictions

- **Acknowledged-issue policy is the inverse of krait Gate H** (krait: README/known-issue mechanism match = unconditional kill; dlt: docs never kill, need code-level proof of the fix).
- Validation verdict scale (`confirmed/likely/unclear/invalid` + `likely/security-hardening`) is softer than krait's "no likely, when in doubt kill."
- SKILL.md/AGENTS.md forbid re-adding the learning loop ("Do not add or reintroduce learning-loop features, benchmark ground truth… unless the user explicitly asks"), while the README's core value story *is* that training loop — a deliberate, documented scope split (training repo vs runtime repo), but the runtime therefore cannot self-improve.

## Gaps

No Solidity/DeFi pack in this snapshot (packs target Rust/Go node codebases: Monad, Fuel, Nibiru, Omni); validation is reasoning-level only (no PoC execution phase); no ranker/report polish; corpus is DLT-fix-specific; everything depends on external Codex/Claude workers.

## Classification

**Core methodology for attack-surface enumeration + validation gating** (the mapper/validation prompts are portable to EVM); **specialized sub-skill pattern** (per-venue design packs); **judge mechanism** (blind suites).



---

# 4. Grimoire (JoranHonig) — `grimoire/`

## Contribution summary

A **co-auditor toolkit**: "the real power of agents is in amplifying operator skill." Specs (human-written `grimoire/` directory) + implemented skills. Core artifacts: GRIMOIRE.md context map (summon), cartography (flow→code maps), librarian (reference-only external knowledge), familiar (skeptic triager), scribe (turns confirmed findings into static-analysis modules/skills for the next audit), checks (minimal markdown vuln patterns), finding lifecycle skills (draft/review/dedup), and an opinionated write-poc workflow.

## Most valuable techniques

1. **Backpressure — never ask a completeness question without a mechanical checker:**
   > "Only allow autonomy with back-pressure methods available. Example: Find me all locations where X happens. Back pressure: A semgrep module that actually finds all locations where X happens. **You should never, ever, ask a completeness question to an agent that can not be backed up with a back-pressure skill.**"
   > "Proof of concepts for findings are a great example of a task that naturally induces back-pressure."

2. **(Trivial) verifiability / falsifiability distinction:**
   > "You can ask questions like: find me all locations in the code where user input is stored. (easy to disprove a claim by finding a counter-example)… You can also ask: is there a location in the code that does input sanitation. (easy to prove a claim by checking the example given). These are very different and you should pick your questions carefully!"
   > "A claim `this location uses sanitisation` is verifiable, the claim `only this location uses sanitisation` is not."
   > "Treat the output to such questions as radioactive. Trust the agent to provide you with interesting data. Never trust it to provide you the correct answer."

3. **The original sin — design against researcher complacency:**
   > "In designing grimoire I'm looking to provide tools that **do not make security research easy**. Instead, grimoire's goal is to remove friction and provide leverage so you can think harder."

4. **Gadgets — index benign primitives as exploitability assets:**
   > "gadgets are tricks I found that allow me to have the code do something unexpected. Usually on their own these gadgets are benign… These gadgets are often essential in enabling critical vulnerabilies to be exploitable… it might be interesting to augment my workflow such that an agent indexes my gadgets and suggests them when I'm considering whether an issue can be exploited."

5. **Scribe loop — every confirmed finding becomes a detector for the next audit:**
   > "The idea is to kick off the scribe agent as soon as we've confirmed and logged a new finding… identify the best method for automatically finding similar issues in future audits. It's strongly preferred that this takes the shape of a static analysis module… immediately run the detector / skill on the rest of the codebase to find variants; have a methodology for identifying false positives generated by previously enscribed methodologies."
   Autonomous detection is explicitly baseline-raising, not complete: "Our goal is to sift out as many bugs as possible before we start. That way all our effort goes into finding hard to discover or automate bugs."

6. **Familiar — skeptical triage with structured outputs** (Impact; Feasibility with *attacker class* + *prerequisite predicate*; Design Intent with a surfaced yes/no question; Scope Cross-Reference). Review gate: "Missing or vague preconditions are a review failure — they are what the reader uses to decide whether the finding applies to their deployment." Character spec: "familiars are sceptics, they don't assume, they verify… they are honest and know their limitations."

7. **Librarian — reference-only answers:** "extremely detail oriented and will only produce claims backed up with references. It's goal is never to provide answers on it's own… It's better for agents to use the librarian than to guess based on their own knowledge."

8. **Finding-quality rules:** title must encode where/how/what; findings self-contained; **"A recommendation should never suggest non-trivial code changes… by suggesting complex implementations we become biased."**; "Findings should always be fact checked, we can't ever have a case where we refer to a best practice or issue that does not actually exist."

9. **Dedup classification:** "A good rule of thumb is that you can delete one of a pair of duplicate findings without losing information, you can not do the same for findings which are *similar*." Never delete/merge without explicit user confirmation.

10. **write-poc as opinionated workflow:** fixed phases, vulnerability-class→reference table, user confirmation gates, familiar as skeptical reviewer of the produced PoC, and "Monetary Impact… Measure attacker balance before and after the proof of concept and determine profit. Print this profit so the user can verify." Claims this "raises [one-shot success] to approximately 90%" vs 60% for unstructured prompts.

11. **Checks — minimal pattern files:** "**Many simple checks beat one complex check.** … Agent attention is the scarcest resource — keep checks focused and short. When reasoning gets complex, split into multiple checks." Check format includes `severity-default`, `confidence`, and attribution fields.

12. **Cartography — reusable flow maps that don't carry content:** files "do not hold the actual context themselves. The goal is merely to provide the information necessary to enable agents to build context on their own" — with conditional sections "to prevent context pollution."

## Contradictions

- Grimoire's philosophy (human-led, "you are responsible for your findings", agents raise the baseline) is in direct tension with krait/hound/dlt's full-autonomy claims; grimoire's scribe spec is explicit: "I see full autonomous agents mostly as something to raise the baseline rather than as real tools that help me during an audit."
- Familiar is both "sceptics… they verify" and "helpful, if there is something they can figure out on their own… they will do so" — the boundary between verifying and reasoning-inventively is unresolved.
- Librarian's reference-only discipline vs familiar's permitted reasoning relies purely on role naming; nothing mechanical enforces it (unlike krait's `enforceGateContract`).
- Verdict softness vs krait: familiar returns `Uncertain / Possibly By Design / Dismissed` where krait kills unconditionally; grimoire keeps humans in the loop, krait replaces them with gates.

## Gaps

No detection heuristics corpus (checks are a skeleton); no severity discipline; no falsification gate in write-poc (krait-poc is strictly stronger); no benchmarks; librarian depends on paid APIs (Solodit, Context7) with web-search fallback; cartography swarm (100 sub-agents) is expensive and unmeasured.

## Classification

**Specialized sub-skills** for co-auditor patterns (backpressure, trivial verifiability, gadgets, scribe-distill, familiar, checks); **reference material** for design philosophy; **validation mechanism** (finding-review, familiar triage); **tool integration** (librarian, cartography, GC skills).

---

# 5. Nemesis Auditor — `nemesis-auditor/`

## Contribution summary

An orchestrator skill running an **iterative back-and-forth loop** between a Feynman Auditor (first-principles interrogation, 7 categories / 28+ questions) and a State Inconsistency Auditor (coupled-state pair analysis, 8 phases), alternating until convergence (max 6 passes), with per-finding **discovery-path tagging**. Language-agnostic (Solidity/Move/Rust/Go/C++/Python/TS). Krait's detector + state-auditor phases are the evolved descendants of this design (same phase numbering, same coupled-pair vocabulary).

## Most valuable techniques

1. **Alternating convergence loop with delta-only re-passes:**
   > "Pass 3+ are TARGETED — only audit new items surfaced by the previous pass. Do NOT re-audit what was already cleared… Each pass MUST produce a delta — what's NEW compared to all previous passes. The delta is what feeds the next pass. No delta = convergence."

2. **Cross-feed value accounting via discovery paths:**
   > "Track the DISCOVERY PATH for every finding. Findings that emerged from cross-feed (e.g., 'State gap in Pass 2 → Feynman root cause in Pass 3') are the highest-value discoveries — they prove the loop's worth." Final tags: "Feynman-only" / "State-only" / "Cross-feed P[N]→P[M]".

3. **The intersection rule:**
   > "RULE 4: PARTIAL OPERATIONS + ORDERING = GOLD. The intersection of 'partial state change' (State Mapper's specialty) and 'operation ordering' (Feynman's Category 2 & 7) is where the highest-value bugs live."

4. **Defensive code as signal:** "RULE 5: DEFENSIVE CODE IS A SIGNAL, NOT A SOLUTION. When the State Mapper finds masking code (ternary clamps, min caps), Feynman interrogates WHY it exists. The mask reveals the invariant that's actually broken underneath."

5. **Evidence-or-silence:** "RULE 6: EVIDENCE OR SILENCE. No finding without: coupled pair, breaking operation, trigger sequence, downstream consequence, and verification."

6. **Per-severity verification requirements:** Critical → MANDATORY PoC ("Must demonstrate value loss or permanent DoS with concrete numbers"); High → code trace + PoC recommended; Medium → code trace minimum.

7. **Attacker-mindset recon before reading code:** "Q0.1: ATTACK GOALS — What's the WORST an attacker can achieve? List top 3-5 catastrophic outcomes. These drive the entire audit… Q0.2: NOVEL CODE — What's NOT a fork of battle-tested code? Custom math, novel mechanisms, unique state machines = highest bug density." Plus Q0.5 pre-code coupling hypotheses: "Build the initial coupling hypothesis BEFORE reading code. The code will confirm or reveal more."

8. **Anti-hallucination protocol:** NEVER "invent code that doesn't exist… assume a function has an access guard without verifying… use phrases like 'could potentially'"; ALWAYS "read the actual code before questioning it… confirm guard/access-control behavior by reading the actual implementation… show exact file paths and line numbers."

9. **FP pattern list** (auth elsewhere, rounding cleaned downstream, validation downstream, bounded loops, severity inflation, language safety) — the ancestor of krait's FP-1…FP-10.


## Contradictions

- No kill gates; verification relies on "attempted disproof" prose + a 6-item FP list — far weaker precision control than krait (which inherited and hardened this exact material). Same lineage, different strictness.
- The convergence loop has no guard against re-litigating already-cleared code except agent compliance ("Never re-audit what was already cleared") — no exclusion-list mechanics like krait's rescan.
- "Every C/H/M finding MUST be verified" vs "LOW verified by inspection" is fine, but the loop's "suspects" from Feynman pass 1 are allowed to be vague by design ("exposed assumptions reveal new coupled pairs"), which the final gate must later clean up — a recall-first stage with no explicit traceability of which suspects died where.

## Gaps

No PoC harness details beyond one-line forge commands (no pinning/falsification); no heuristics corpus; no recon risk scoring; no dedup/consolidation rules; no audit-trail fields; no benchmarks; state-auditor Phase 8 says "Verification Gate" but is thinner than krait's critic.

## Classification

**Core methodology contributor** — the cross-feed convergence loop + discovery-path tagging are the unique, reusable pieces; otherwise **superseded by krait** (use krait's versions of the same Feynman/state phases, which carry kill gates and audit-trail fields).

---

# 6. open-kritt — `open-kritt/`

## Contribution summary

Self-hosted platform (built by Blockian researchers, ~$1.5M bounty payouts) for **workflow-based multi-agent scanning**: decompose research into small tasks, fan out across Codex/Claude Code harnesses, then validate, dedupe, rank, and export. Key mechanics: depth/sibling workflow graph with bind routing and batching, repeat runs, per-finding post-scripts (validation verdicts, patched-since, report creator, PoC creator, bounty-scope check), plain-Markdown severity rankers, a fixed finding schema, and share-safe export.

## Most valuable techniques

1. **Focused decomposition over whole-repo prompting:**
   > "Pointing a model at an entire repository and asking it to find vulnerabilities rarely works well. open·kritt takes a focused approach: break the research into small, well-defined tasks, run them across AI agents in parallel, and combine their output into findings you can validate and prioritize."

2. **The proven external-flow-analysis workflow (three stages, one path per final agent):**
   > "Enumerate entrypoints → Trace reachable flows → Investigate each flow… This decomposition saves context. Entrypoints and flows are mapped once, while each final agent spends its context window on one concrete path." ("has helped us find vulnerabilities that resulted in multiple bug-bounty awards.")

3. **Per-target workflow specialization** (e.g., Cosmos ABCI panic halt review fans out four panic-class investigations per method; "Each investigator returns only maliciously triggerable, production-reachable halt paths").

4. **Execution-model controls:** depth-ordered levels; sibling steps sharing one schema; **bind routing** (one-to-one source→destination mapping, validated for completeness); batching modes "one at a time" vs "all at once" (`multi_output_depth_N` arrays for dedup/ranking steps).

5. **Repeat runs with append-only semantics:** "every later repeat receives only the earlier output from that exact task… It is told to append genuinely new results without restating the existing set."

6. **Post-script validation as a cheap per-finding gate:**
   > "Re-check '{{summary}}' ({{vulnerability_type}}) at {{file_path}}:{{line}}. Is it exploitable in a default deployment? Return: verdict (string): CONFIRMED, LIKELY, or FALSE_POSITIVE."

7. **Patched-since check** — path-scoped diff + commit history against the remote default branch without moving the pinned checkout; "If the default branch cannot be fetched, does not descend from the scan commit, or the finding path is unsafe, it requests manual review instead of guessing."

8. **Finding schema forces attack concreteness at capture time** (`trigger_flow`, `malicious_input_example`, `malicious_actor` fields) — the platform-level analogue of krait's "WHO calls WHAT with WHICH params".

9. **Severity rankers encode per-program triage in plain Markdown:** "a ranker lets you say things like 'auth bypasses on money-moving endpoints outrank everything else'… so the ordering reflects real payout potential." Runs **after dedup**, supports full rerank or append.

10. **Share-safe export:** "Attacker-influenced report and PoC source is kept as plain text"; completed vs partial exports clearly marked — adversarial-modeling of the *tool itself*.

11. **Platform threat model for scanning untrusted code** (root in disposable containers, credential scoping, dedicated host) — required reading for anyone hosting agent-based auditors.


## Contradictions

- Validation is a **soft gate** (CONFIRMED/LIKELY/FALSE_POSITIVE post-script) vs krait's mechanical kill gates; open-kritt deliberately defers to humans + rankers ("Cut noise by grading each finding's exploitability before a human ever looks at it") while krait removes the human from the loop.
- Repeat-run dedup relies entirely on model compliance ("told to append… without restating") — DLT achieves the same isolation goal mechanically via blind-suite workspace separation (stronger).
- Minimal-prompt philosophy (workflow steps are short) vs krait's 613-line detector prompt — opposite theories about context budgets.
- Workflows emit findings krait's gates would mass-kill; the two cannot be composed without a gate layer between them.

## Gaps

Zero detection content (workflows are user-defined; no heuristics/knowledge base); no PoC pinning (PoC Creator is unbounded); no falsification gate; no measured precision/recall in-repo; heavy infra (Docker, engine, Postgres); no harm-assertion requirement in the finding schema (impact is prose).

## Classification

**Tool integration** (multi-agent workflow orchestration platform); **validation mechanism** (post-scripts, rankers, dedup); **reference material** for workflow decomposition patterns (depths/siblings/bind/batch/repeat).

---

# 7. SolidityGuard — `SolidityGuard/`

## Contribution summary

An agent-team audit command (`/solidity-guard:deep-audit`) that orchestrates a team lead + 5 specialized teammates (Reentrancy, Access Control, DeFi/Oracle, Logic/Math, Adversarial Reviewer) over a shared, self-claiming task list, with a static baseline (Slither + Aderyn), dynamic PoC verification (`/verify-exploit` with per-pattern fork templates), fuzzing (`/generate-fuzz`), a 104-pattern ETH-xxx taxonomy, a notable-exploits knowledge base, and an honest CTF test matrix validating its own scanner.

## Most valuable techniques

1. **Adversarial reviewer as a blocked, separate task** (krait's critic as a teammate):
   > "Your job is to CHALLENGE findings from the other teammates… For EACH finding, attempt to DISPROVE it… Classify each finding: TRUE POSITIVE / FALSE POSITIVE / DOWNGRADE / UPGRADE."

2. **Consensus-based confidence with disagreement override:**
   > "Three+ teammates agree → Cap at 95%. Adversary confirms → +5%. Adversary disproves → Finding rejected. Slither/Aderyn agrees → +10%." (Team-lead synthesis rule — cross-agent agreement as evidence weighting.)

3. **Self-claiming shared task list** ("Teammates self-claim unblocked tasks") with dependencies expressed via blocking ("This task is blocked until the 4 audit tasks complete").

4. **Static tools as baseline first** (Slither + Aderyn before agent spawn) — cheap coverage before expensive reasoning.

5. **Per-pattern PoC templates with tool selection table** ("Vulnerability Type | Best Tool | Why" — e.g., ETH-024 Oracle Manipulation → "Foundry fork test: Need real oracle state") and a **state-diff report** format (before/after balances per actor, "VERIFIED — Full vault drain").

6. **Per-finding evidence requirements for every teammate:**
   > "For each finding, provide: Vulnerability ID and severity, Exact file:line code location, Verbatim vulnerable code snippet, Numerical example showing the exploit, Recommended fix with code."

7. **Notable-exploits KB as pattern source:** every entry maps a real hack to a pattern ID, root cause, attack sequence, and lesson ("Beanstalk — Pattern: ETH-025 + ETH-055 (Flash Loan + Governance) — Lesson: Snapshot voting, timelock on execution, flash loan protection").

8. **Self-benchmarking honesty via CTF matrix:** "Current detection rate: ~10/31 contracts (32%) via pattern scanner alone. With Slither+Aderyn: estimated 22/31 (71%)." — explicit capability boundary per pattern.

## Contradictions

- Consensus boosting can **increase confidence in a systemic FP** (four agents agreeing on the same wrong assumption); krait's gates exist precisely to break that failure mode — SolidityGuard has no mechanical gate against it (adversary is one more same-model agent).
- Adversarial reviewer is asked both to "CHALLENGE" and rewarded with "+5% additional" for confirming — incentive ambiguity.
- Adversarial reviewer may UPGRADE severity; krait's critic "Never add new findings" and only downgrades.
- CTF matrix shows the scanner can't detect semantic classes (oracle, flash loan, signature replay, storage collision) — the team-of-agents is doing the real work; the ETH-xxx taxonomy advertises 104 patterns that the machine layer largely cannot see.

## Gaps

No kill gates / impact premise / exploit-trace requirement beyond the PoC templates; no recall/precision measurement of the agent team itself; no recon/risk-scoring phase; no dedup or root-cause consolidation; static knowledge base (no scribe-like learning loop); team prompts are per-domain checklists rather than first-principles frameworks.

## Classification

**Specialized sub-skill** (multi-agent team orchestration + consensus confidence); **reference material** (exploit KB, CTF test matrix, ETH-xxx taxonomy); **tool integration** (scanner, fuzz, PoC templates).


---

# 8. ZeroSkills (Zero Cool) — `ZeroSkills/`

## Contribution summary

Five zero-shot, **out-of-distribution** detection skills: `slot-sleuth` (EVM storage safety), `vyper-vanguard` (Vyper), `symmetry-sniper` (paired-operation asymmetry), `univ4-hook-harbinger` (Uniswap v4 hooks), `test-terminator` (test-suite analysis). Explicit theory: "The vulnerabilities that win contests and matter in production tend to live outside what frontier models already know. A skill is useful when it extends the model's effective knowledge boundary." Claims production validation (240 confirmed findings from symmetry-sniper; 84 from test-terminator; a Code4rena H-01).

## Most valuable techniques

1. **Out-of-distribution targeting as the selection criterion for what deserves to be a skill** (anti-pattern: "Most public security skills restate well-documented patterns… Frontier models already encode this knowledge").

2. **Applicability gates on every skill** — refuse to force findings:
   > "Only proceed if BOTH conditions are true… If these gates are not satisfied, do not force findings." (slot-sleuth); "Otherwise do not force findings." (all five).

3. **Per-phase report conditions with explicit benign exclusions** — e.g. lost-write requires all four conditions including "The surrounding logic indicates that persistence was expected," and "Do not report if: the function is clearly `view` or `pure`… intentionally constructs and returns a modified copy… the variable is actually a storage reference."

4. **Named overwrite targets** for slot-write findings: "Examples of realistic overwrite targets: owner or admin variables, configuration parameters, balances or accounting mappings, implementation or proxy slots, governance roles."

5. **Test-terminator — the tests-as-security-intelligence skill** (unique in the cluster):
   > "Treat existing tests and missing coverage as security intelligence… Tests and missing coverage are clues, not proof. Confirm every finding in reachable production code."
   Probes: extract invariants encoded by tests; "Treat fixtures and mocks as assumptions… Ask whether a user can reach the same production function without satisfying the fixture's preconditions"; hunt fuzz filters ("`assume`, `bound`… For each excluded class, determine whether it is reachable in production"); "Compare what a test promises with what it proves… Tests named 'full,' 'all,' 'final,' 'zero,' 'unauthorized,' or 'reverts' that stop short"; cross-suite conflicting assumptions.

6. **Symmetry-sniper — pair diffing as a detection primitive:** "Diff state and value across the pair… Authorization parity… Rounding, fees, and round-trips… Batch versus single parity." Includes single-vs-batch as a pair class most auditors ignore.

7. **Univ4 hooks — ecosystem-boundary reasoning:** "The skill treats the hook as one component of a protocol and traces routers, pools, vaults, and protocol-issued tokens alongside it. If `beforeSwap` offsets the native swap into a no-op, the hook is the entire AMM and gets reviewed as one." Reports only with "a reachable attacker path, the exact callback and settlement sequence, the false assumption, the broken invariant, and who gains and loses."

8. **Vyper Vanguard — demote CVE archaeology:** "explicitly demotes compiler-CVE matching as a side branch — it records the version for sharpening evidence but requires a concrete exploit path before reporting any version-dependent bug."

## Contradictions

- ZeroSkills target exactly the novel/edge classes that krait's gates A/B/G are tuned to kill (exotic token behavior, storage semantics, test-assumption gaps); both demand concrete impact, so they align on the Impact Premise but diverge on default skepticism toward "theoretical" classes. Compose carefully: run ZeroSkills *before* krait's critic, or their value is destroyed.
- slot-sleuth allows "credible risk during upgrades → report as an **upgrade-safety risk**" — a class krait Gate C/E and grimoire's recommendation rules would filter or reword.
- "Zero-shot" branding conflicts with the stated mechanism (injecting post-training, experience-derived knowledge) — intended meaning is "no fine-tuning," but the label is misleading.

## Gaps

No pipeline, no severity calibration, no verification gate (only "clear security impact" prose), no dedup/report format, no benchmarks beyond unverifiable counts; EVM-only.

## Classification

**Specialized sub-skills** (detection heuristics for out-of-distribution classes) — the highest-density pattern for the unified skill: applicability gates + per-phase report/do-not-report conditions. `test-terminator` is uniquely valuable and has no equivalent anywhere in the cluster.


---

# 9. AI (web3-security claude skills) — `AI/`

## Contribution summary

Two small, single-purpose Claude Code skills: `protocol-breakdown` (`/breakdown`) — a full mental-model briefing of a protocol before hunting — and `findings-writer` (`/write-the-finding`) — judge-proof finding writeups formatted for Code4rena/Sherlock/Cantina/Immunefi.

## Most valuable techniques

1. **Protocol breakdown discipline:**
   > "Read EVERYTHING before producing any output. Do not start writing after reading 3 files." Layers: docs (incl. previous audits + known-issues lists), code in full, tests/scripts/configs ("reveal developer intent, expected behavior, and what they didn't test"), invariant/property tests ("direct statements of what must be true").
   > "Numeric examples for all non-trivial math — if there's a formula, show numbers through it."; "Don't trust the README — verify claims against code. If README and code disagree, flag the discrepancy."; "Flag uncertainties — mark with '⚠️ UNCLEAR - [what and why]'."
   The battle plan must name "specific file, function, line range, and what bug pattern to look for" plus cross-contract pairs and fuzzing targets; bad/good examples: Bad: "Check Vault.sol for reentrancy." Good: "Vault.sol:withdraw() calls strategy.withdraw() at line 142 before updating user shares at line 148… creates a reentrancy window."

2. **Findings-writer — judge-proof prose rules:**
   > "Impossible to Invalidate — Base all arguments on code behavior… Avoid speculation or hypothetical claims without proof."; "Extremely Clear and Simple — Judges must understand the issue immediately"; "Concise but Complete — Short enough to read in under 1 minute. No filler text."; relative code links with line anchors; append-only file handling ("Never overwrite existing findings").

## Contradictions

- The three context-building conventions compete: krait's `.audit/recon.md`, grimoire's `GRIMOIRE.md`, and this skill's chat briefing — a unified skill must pick one canonical artifact.
- Finding structure (Summary/Root Cause/Vulnerability Details/Impact/PoC/Mitigation) differs from grimoire's (Description/Details/PoC/Recommendation/References) and krait's reporter format — three schemas, no interop.
- findings-writer has no severity calibration or gate; "Impact" prose can be inflated — it explicitly says "Do NOT exaggerate impact" but nothing enforces it.

## Gaps

No detection/validation/PoC/gates; skills are presentation-layer only.

## Classification

**Reference material** — output formatting for platform submission (judge-facing) and context-briefing patterns.

---

# 10. defi-builder-skills — `defi-builder-skills/`

## Contribution summary

Two **builder-side** plugins (defi-protocol-discovery, defi-spec-driven) for spec-driven DeFi development. Not an auditor — but its Phase 4 `threat-model.md` is the best **pre-audit / design-time threat modeling** spec in the cluster, and its invariant-first ordering is directly reusable by audit recon phases.

## Most valuable techniques

1. **Per-function threat model entry with specific value-at-risk:**
   > "What 'value at risk' means: Be specific. Not 'user funds' — but 'user's proportional share of vault assets, up to totalAssets.' The specificity matters because it drives the severity assessment and the mitigation priority."
   Entry format: Caller / Value at risk / per-vector Mechanism / Conditions / Mitigation / Residual risk / Open questions.

2. **Context-driven, explicitly anti-checklist:**
   > "Do not use a fixed checklist. Think freely per function… A checklist applied mechanically produces false confidence. Context-driven analysis produces real security." — the strongest counterweight in the cluster to krait's/SolidityGuard's checklist philosophy (worth preserving as a *dialectic*, not a winner).

3. **Two-pass analysis with a blind LLM second pass:**
   > "Do not give it the vectors you already found — you want an independent perspective, not a confirmation… Your analysis has the protocol context the LLM lacks; the LLM has breadth across DeFi patterns that complements your focus." (Independence-first, exactly opposite to SolidityGuard's consensus boost — the right pattern is *independence, then* agreement.)

4. **Emergency-mechanism analysis with the critical question:**
   > "Can users still withdraw in a paused state? (This is the critical question — a pause that traps user funds creates a new attack vector.)"

5. **One-agent-per-function parallel threat modeling:** "The workflow spawns one agent per function, all running concurrently… The workflow handles breadth; your review handles quality."

6. **Invariant-first phase ordering** (Phase 1 category exploit patterns → Phase 2 economic invariants → Phase 3 access control → Phase 4 connect both to every function) — invariants and who-can-call-what are fixed *before* per-function analysis, giving every function entry a context to check against.

7. **Done-when gates with file naming:** "name the path of each file created this phase. If you cannot name it, it does not exist — create it now."

## Contradictions

- "Do not use a fixed checklist" directly opposes krait's 101-heuristic checklist-driven detector and SolidityGuard's per-domain pattern lists — the unified skill must decide when checklists help (recall triggers) vs hurt (false confidence), i.e., krait's own rule: heuristics are "triggers, not a checklist to recite" is the reconciling stance.
- Built for designing new protocols, not auditing existing ones — its attack-vector enumeration assumes a benign designer; krait assumes an adversarial one.

## Gaps

No exploit verification; no severity scheme; no findings pipeline; EVM/DeFi only; "Phase 1 surfacing exploit patterns" is left to other sources.

## Classification

**Reference material** — threat-modeling and spec-driven security; **specialized sub-skill** for invariant extraction that can feed audit recon.


---

# Unified Synthesis

## Recommended architecture for the unified security skill

- **Core pipeline:** krait (preflight → recon → detection passes → state auditor → critic → reviewer → reporter), because it is the only pipeline with *measured* precision, mechanical gates, and an audit trail.
- **Orchestration upgrades:** hound's scout/strategist separation + coverage→saliency phase planning with WHY-NOW/EXIT-CRITERIA; nemesis' convergence loop + discovery-path tagging; SolidityGuard's self-claiming task board + adversarial reviewer; open-kritt's depth/sibling/batch decomposition for parallelism.
- **Detection content:** krait's 101 heuristics + ZeroSkills' out-of-distribution skills (all with applicability gates) + test-terminator; grimoire checks + scribe loop to convert every confirmed finding into a new detector with an FP-measuring methodology.
- **Threat modeling:** DLT's protocol mapper (attack-surface matrices) + defi-builder-skills' per-function entries (value-at-risk specificity, blind second pass) as the recon output shape.
- **Evidence gates:** krait kill gates A–H + Impact Premise (harm, not mechanism) + DoS exception + Gate-H mechanism matching; krait-poc falsification gate (defect-mutation pinning + fix-efficacy + negative control) as the mandatory verification step; batch triage lanes with recall-safe demotion.
- **Knowledge:** grimoire librarian (reference-only claims) + backpressure rule ("never ask a completeness question without a mechanical checker") + trivial-verifiability question design.
- **Judge mechanism:** krait's shadow-audit regression (blind, precision-gated) + DLT's blind-suite isolation rules.

## Conflicts a unified skill must resolve explicitly

1. **Acknowledged issues:** krait kills (Gate H) vs DLT requires code-level proof of the fix before suppression. → Adopt: kill only on *exact mechanism match* AND current-code evidence the mechanism is fixed; otherwise report at reduced priority.
2. **Evidence strictness:** krait "no likely/insufficient evidence, when in doubt kill" vs dlt/open-kritt/nemesis verdict ladders. → Keep krait's ladder for the main report but preserve a "Worth Manual Review" escape hatch (krait's reviewer) so over-kills are recoverable.
3. **Admin-trust findings:** krait kills (Gate E) vs grimoire/defi-builder report with conditions. → Adopt krait's downgrade (A5) + exception for irreversible destructive actions without timelock, and *always* answer defi-builder's "can users withdraw while paused" question in recon.
4. **Checklists vs context:** SolidityGuard/krait lists vs defi-builder's anti-checklist. → krait's own reconciliation: heuristics are *triggers matched against code*, never recited.
5. **Context budgets:** krait's 613-line detector prompt vs grimoire's ≤30-line checks vs open-kritt's minimal steps. → Shrink the *always-loaded* prompt (krait v7 already measured that shrinking improves adherence), move detail to *load-on-trigger* modules (krait's module/primers + grimoire's conditional cartography sections).
6. **FP handling:** mechanical gates (krait) vs confidence scores (hound) vs adversarial review + consensus (SolidityGuard). → Gates first (cheap, deterministic), adversarial review second (independent model), consensus boosts only as *secondary* signal — never as a substitute for a gate, because agreeing agents share failure modes.

## Gaps across the whole cluster (opportunities)

- No repo performs **differential auditing against the fork origin** as a mechanical phase (only krait's fork check and ZeroSkills' storage/upgrade skills touch it).
- No **cross-model ensemble judging** (every verdict is single-model); nothing validates on-chain state against the finding's claimed precondition.
- No **cost-aware planning** (hound's exit criteria and grimoire's backpressure point at it; nobody budgets tokens per finding).
- Weak **upgrade/diff-audit** support (slot-sleuth is the only dedicated storage-layout safety skill).
- krait's audit-trail precondition/postcondition fields are designed for **cross-finding chain analysis** but no engine actually chains findings yet — the highest-leverage unexploited feature in the cluster.

