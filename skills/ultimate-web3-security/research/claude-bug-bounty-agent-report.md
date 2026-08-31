# claude-bug-bounty — Web3 Material Extraction Report

**Repo:** `/home/nishan/ultimate-web3-security/sources/claude-bug-bounty`
**Scope of analysis:** `web3/*.md`, `agents/{web3-auditor,validator,report-writer,recon-ranker}.md`, `commands/arsenal.md`, `tools/{validate.py,scope_checker.py}`, `SKILL.md`, `CLAUDE.md`. General web pentest content was only consulted where triage/severity/reporting rules are shared.

---

## 1. Contribution Summary

claude-bug-bounty is a Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti and Immunefi. Its web3 layer is a curated 15-file skill chain whose credibility rests on empirical frequency data rather than theory: `web3/00-START-HERE.md` states it was "Built from: 2,749 Immunefi reports + 100+ paid writeups + DeFiHackLabs (681 hacks) + ConsenSys + SlowMist + Trail of Bits + Foundry + Nethermind + Lido + AI agent research + live hunt experience." The distinctive contribution is a **frequency-ordered hunt pipeline with kill-gates at every stage**: pre-dive target scoring (TVL/audit/payout gates), a 10-class DeFi bug taxonomy ranked by observed % of Criticals (accounting desync 28%, access control 19%, incomplete path 17%), a copy-paste grep arsenal with tiered triage of hits, a production Foundry PoC template plus 18 dissected paid exploit templates, a "7-Question Gate" triage system with an Immunefi impact-tier severity list and a 3-axis severity matrix, 20 real paid findings reduced to three universal root-cause patterns, and external methodology synthesis (Trail of Bits Echidna/Medusa, Immunefi Web3 Security Library, Nethermind's 166 public audits). It extends to adjacent surfaces (meme-coin rug vectors, Solana SPL/Token-2022 authorities, DEX/LP manipulation) and includes a rare "defense study" — a completed ZKsync Era hunt with 25 tested attack vectors and 0 findings — documenting *when to abandon a target*. The web3 layer reuses the shared web2 validation stack (`agents/validator.md` 7-Question Gate + 4 gates, `tools/validate.py` CVSS 4.0 + duplicate search, `tools/scope_checker.py` deterministic allowlisting, `agents/report-writer.md` report standards); severity/reporting rules are shared at the *gate* level but diverge at the *scoring* level (Immunefi impact tiers vs CVSS), producing several contradictions noted in §3.

---

## 2. Most Valuable Techniques & Gates (verbatim-worthy)

### 2.1 The Bug Validation Template — the universal finding gate
`web3/01-foundation.md:25-35`. Every finding must be filled in before writing anything:

```
I am an attacker. I will:
1. SETUP:   What do I need? (wallet, capital, any whitelisted permissions?)
2. CALL:    Exact transactions, exact order, exact function names
3. RESULT:  What do I end up with that I didn't start with?
4. COST:    Gas + capital + flash loan fee + any other expense
5. DETECT:  Can anyone stop or reverse this?
6. NET ROI: I gained X at cost of Y. Is Y << X?
```

> "If you can't fill in steps 2 and 3 with specific function calls → **it's not a real bug. Stop. Move on.**"

This is the single best falsification gate in the repo: it forces an exact call sequence and a profit delta, eliminating "technically possible" findings before PoC effort is spent.

### 2.2 The ONE RULE — sibling-function modifier check (19% of Criticals)
`web3/00-START-HERE.md:60`:

> "Read ALL sibling functions. If `vote()` has a modifier, check `poke()`, `reset()`, `harvest()`. The missing modifier on the sibling IS the bug."
> "This single rule explains 19% of all Critical findings."

`web3/01-foundation.md:48-50` repeats it as Attacker Question #10 and adds the framing "Inconsistency Is Proof" (`01-foundation.md:78`): "If `functionA()` has a security check, and `functionB()` doesn't — **that IS the report.**" This is also the backbone of Class 2 in `agents/web3-auditor.md:56` ("The ONE RULE: Read ALL sibling functions. If `vote()` has modifiers, check `poke()`, `reset()`, `harvest()`").

### 2.3 The 6 Triager Counter-Questions — self-kill before PoC
`web3/01-foundation.md:52-63`. Before spending time on a PoC, try to KILL the finding; "**One YES = KILL. Move on.**":

1. Is there an upstream check I missed that actually prevents this?
2. Is this documented intended behavior (whitepaper, NatSpec, design decision)?
3. Does exploitation require admin/privileged access? (Usually invalid if yes)
4. Is the economic cost to exploit greater than the gain? (Not viable if yes)
5. Was this flagged in a prior audit as "acknowledged" or "risk accepted"?
6. Is the "sensitive" data already publicly visible to anyone in the web UI?

### 2.4 Pre-Dive Assessment — target-worthiness gates
`agents/web3-auditor.md:20-25` (ALWAYS run before reading code):

```
1. TVL check: < $500K → too low → STOP
2. Audit check: 2+ top-tier audits (Halborn, ToB, Cyfrin, OZ) on SIMPLE protocol → STOP
3. Size check: < 500 lines, single A→B→C flow → minimal surface → STOP
4. Payout formula: min(10% × TVL, program_cap) → if < $10K → STOP
```

Then a scorecard (lines 28-36): "TVL > $10M: +2", "Immunefi Critical >= $50K: +2", "No top-tier audit on this version: +2", "< 30 days since deploy: +1", "Upgradeable proxies: +1", "Protocol you know well: +1" → "Proceed if >= 6/10". The ZKsync hunt (`web3/09-live-hunt-zksync.md:168-174`) adds a hard-won refinement:

> "SOFT KILL: If protocol has OZ/ToB/Cyfrin audit on current version AND codebase > 500K LOC → expect 40+ hours for MAYBE 1 finding → only proceed if bounty floor > $50K AND you have protocol-specific expertise"

### 2.5 The 7-Question Gate (shared with web2, adapted to web3)
`web3/05-triage-report-examples.md:12-105` and `agents/validator.md:24-55`. Applied **in order**; "First NO = KILL immediately." The web3-specific phrasing:

- **Q1** — complete the Setup/Call/Result/Cost/ROI template: "If you cannot complete steps 2 and 3 with specific function calls: **KILL IT.**"
- **Q2** — "Go to the Immunefi program page. Find 'Impacts in Scope.' Match your bug to one of these EXACTLY." The canonical impact-tier ladder (`05-triage-report-examples.md:39-49`):

```
- "Direct theft of any user funds" — Critical
- "Permanent freezing of funds" — Critical
- "Protocol insolvency" — Critical
- "Theft of unclaimed yield" — High
- "Permanent freezing of unclaimed yield" — High
- "Temporary freezing of funds" — High
- "Smart contract unable to operate due to lack of token funds" — Medium
- "Griefing (no profit motive, but damage to users)" — Medium
- "Contract fails to deliver promised returns, but doesn't lose value" — Low
```

- **Q3** — "Confirm the exact deployed address is in scope on the program page. If the bug is in Aave, Uniswap, OpenZeppelin, or any external dependency: **KILL IT.**"
- **Q4** — "'Admin can drain funds' = centralization risk = **KILL IT.**" with a salvage path: "can the bug trigger WITHOUT the admin doing anything unusual? If yes: valid."
- **Q5** — search prior audits for "Risk Accepted," "Acknowledged," "Won't Fix." Edge case: "acknowledged finding + NEW code around it creates a new attack path → that is a new bug."
- **Q6** — economic viability with two calibrating examples (`05:92-94`): "DoS via dust harvest: costs 1 wei USDC + gas, disables yield for $81K TVL → VIABLE." vs "Withdraw-fee arbitrage: fee (0.1%) > diluted yield from attack → NOT profitable → KILL IT."
- **Q7** — already public / previously disclosed → KILL.

`agents/validator.md:19-22` forces a single verdict per finding: "**PASS** … **KILL [Q#]** … **DOWNGRADE** — Valid bug, but severity overclaimed … **CHAIN REQUIRED** — Valid on the never-submit list but can be chained." Its Fast Kill Signals (`validator.md:100-105`) are worth verbatim adoption: "'Could theoretically...' → no PoC → KILL Q1"; "'Admin can do X' → KILL Q4"; "'Might be chained with...' → build it first → KILL Q1"; "More than 2 preconditions simultaneously required → KILL Q1."

### 2.6 Severity Matrix (3-axis) and the triager-perspective rule
`web3/05-triage-report-examples.md:108-110`: "Score = Impact × Likelihood × Exploitability (each 1–3)" (Impact=1 info leak / 2 partial / 3 theft-freeze; L and E likewise 1–3). Paired with the SKILL.md-level empathy rule (`SKILL.md:978-979`): "Would a triager reading this say 'yes, that's a real bug'? Read your report as if you're a tired triager at 5pm on a Friday."

### 2.7 Foundry PoC standards and exact commands
`web3/04-poc-and-foundry.md:8` sets the evidence bar:

> "Immunefi requires RUNNABLE code. Not pseudocode. Not steps. Running Foundry tests with before/after logs and a passing assert."

Exact scaffold (`04:15-32`):

```bash
forge init my-poc --template immunefi-team/forge-poc-templates --branch default
forge init my-poc --template immunefi-team/forge-poc-templates --branch reentrancy
forge init my-poc --template immunefi-team/forge-poc-templates --branch flash_loan
forge init my-poc --template immunefi-team/forge-poc-templates --branch price_manipulation
# ...
source .env
forge test --match-test testExploit -vvvv --fork-url $MAINNET_RPC_URL
```

Key reproducible-fork + cheatcode techniques: pin the block — `uint256 constant ATTACK_BLOCK = 18_000_000;` and `vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), ATTACK_BLOCK);` with `vm.label(...)` for trace readability (`04:75-91`). The failure-cause table (`04:1104-1113`) encodes hard-won fixups: "`vm.prank()` reverts | Function checks `tx.origin`, not `msg.sender` | Use `vm.startPrank(user, user)` to set both"; "`deal() not working` | Token has non-standard storage | Find storage slot manually with `cast storage`"; "`Out of gas` | … | Add `vm.txGasPrice(0)` and `--gas-limit 50000000`". A frequency table grounds exploit selection (`04:1119-1132`): "Oracle/Price Manipulation 32% … Access Control 19% … Reentrancy 8%" and "**Key insight: 83% of successful exploits used flash loans (zero-cost capital).**"

### 2.8 The 3 Universal Root-Cause Patterns (from 20 paid examples)
`web3/05-triage-report-examples.md:766-785` — the highest-yield abstraction in the repo:

> **Pattern A: "I assumed function B was called, but it wasn't"** — "Fast path skip, early return, conditional execution … ensure ALL paths update ALL state variables"
> **Pattern B: "I assumed the check meant X, but it actually means Y"** — "`_requireOwned` = existence not ownership"; "`>` = doesn't include boundary"; "Modifier = silent bypass when missing"
> **Pattern C: "I assumed this can't happen, but it can"** — "ecrecover can't return address(0) → it can"; "negative amounts can't be passed → they can (felt252)"; "this function won't be called twice → it will"

### 2.9 Grep arsenal with tiered triage
`web3/03-grep-arsenal.md:12-24` — run all 10 blocks in "the first 30 minutes of any new target," collect hits, then: "Tier 1 — Near privileged code, external calls, or state changes with no guards → Investigate first"; "Tier 2 — Interesting patterns that need context"; "Tier 3 — Informational only … Skip unless Tier 1+2 exhausted." High-signal red flags verbatim: "Modifier uses `if (condition) { _; }` without else → Tier 1 (silent bypass — function still executes for unauthorized callers)" (`03:43`); "`onlyOwner` count << total external function count → likely missing guards on siblings" (`03:44`); "`slot0()` used for price → Tier 1 … `getReserves()` used for price → Tier 1 … `latestRoundData` without `updatedAt` check → Tier 1 (stale Chainlink price)" (`03:73-77`). The frequency-to-first-grep map in `02-bug-classes.md:1103-1110` ("Rank 1 Accounting Desync 28% … First Grep `totalSupply\|totalShares\|totalAssets`") is an excellent cold-start ordering table.

### 2.10 Invariant-first fuzzing (ToB synthesis)
`web3/06-methodology-research.md:19`: "**Echidna** | Property-based fuzzer (write invariants, it breaks them) | Write 3-5 invariants before reading code." Template invariants (`06:56-73`): `echidna_solvency` = `vault.totalAssets() >= vault.totalDebt()`; `echidna_share_math` = `vault.balanceOf(address(this)) <= vault.totalSupply()`; `echidna_reward_monotonic` = cumulativeRewardPerShare only increases. Run: `echidna contracts/VaultInvariants.sol --contract VaultInvariants --test-mode assertion`, plus Medusa for "extended campaigns" (`medusa fuzz --config medusa.json`, `"testLimit": 500000`).

### 2.11 Nethermind 5-Minute Critical Scan (validated against 166 audits)
`web3/06-methodology-research.md:1143-1202` condenses the highest-payout bug archetypes into grep-able gates: (1) "Empty array bypass of state reset (Vana) — state flag set after a loop that can be skipped by passing `[]`"; (2) "Duplicate ID in batch operations — same ID passed twice → double credit"; (3) "Uninitialized cache variable — `cachedTotalAssets` starts at 0, first depositor gets all shares"; (4) "Unauthorized offer updates — `updateOffer()` has no `require(owner[id] == msg.sender)`"; (5) "Decimal precision mismatch — 6-decimal token in 18-decimal math rounds collateral to 0". Each ships with its own grep (e.g., `grep -rn "function.*migrate\|function.*batch" src/ --include="*.sol" -A20 # Missing: require(!seen[id]) inside loop`).

### 2.12 Deterministic validation gates in tools/validate.py
`tools/validate.py:873-878` — four named gates, all must pass or the tool refuses to proceed to scoring:

```python
(1, "Is it real?",       g1_pass),
(2, "Is it in scope?",   g2_pass),
(3, "Is it exploitable?",g3_pass),
(4, "Is it a dup?",      g4_pass),
```

Failure behavior: prints `"Failed: {', '.join(failed)}"` and "Resolve the failed gates before submitting." (lines 889-891); final JSON records `"validation_status": "validated_finding" if all_pass else "scanner_hit"` (line 919) — an explicit machine-readable distinction between a validated finding and a raw scanner hit. It then computes **CVSS 4.0** via a macro-vector implementation (EQ1–EQ4 functions + lookup table, lines 49-97), does a duplicate search, and emits a skeleton HackerOne report plus `submission-notes.md` with next steps: "1. Fill in the actual HTTP request + response in the PoC section … 3. Replace all [bracketed] placeholders with specific details" (lines 955-958). The shared web2 pre-submission gates in `SKILL.md:981-1014` add checklist detail: Gate 0 Reality Check (30s) = "confirmed with actual HTTP requests, not just code reading"; Gate 1 Impact Validation (2 min) = "There's a real victim … I'm not relying on the user doing something unlikely"; Gate 2 Dedup (5 min) = "Searched HackerOne Hacktivity … GitHub issues … Read the most recent 5 disclosed reports for this program"; Gate 3 Report Quality (10 min) = title formula, copy-pasteable request, evidence "not just 200 response", "Severity: Matches CVSS 3.1 score AND program's severity definitions."

### 2.13 Deterministic scope checking — scope_checker.py
Header docstring (`tools/scope_checker.py:1-10`) is itself the gate spec:

> "Deterministic scope checker — code check, not LLM judgment … Uses anchored suffix matching (not raw fnmatch) to prevent subdomain confusion: — `"*.target.com"` matches `"sub.target.com"` but NOT `"evil-target.com"` … Known limitation: IP addresses and CIDR ranges are NOT supported (returns False + warning)."

Ordering matters: "Check exclusion list first" (`:77-80`), then allowlist; unknown hostnames and malformed URLs return False (fail-closed); vuln-class blocklist is separate (`is_vuln_class_allowed`); CLI exits with code 2 on any out-of-scope asset or excluded class (`:227-235`) so it can gate automation pipelines.

### 2.14 Known-issue / bounty-excluded bug detection
Three layered lists: (a) Q5/Q7 of the 7-Question Gate (prior-audit acknowledged + already public, §2.5); (b) the **Never-Submit List** in `agents/validator.md:59-79` ("Missing headers (CSP/HSTS/X-Frame-Options) … GraphQL introspection alone … CORS wildcard without credentialed exfil PoC … Self-XSS … Open redirect alone"), with the rule "KILL Q7 or CHAIN REQUIRED"; (c) the **Conditionally Valid** chain table (`validator.md:83-89`: "Open redirect → + OAuth code theft → CHAIN REQUIRED"; "SSRF DNS-only → + internal data → CHAIN REQUIRED"; "S3 listing → + secrets in bundles → CHAIN REQUIRED"). SKILL.md generalizes this as the "ALWAYS REJECTED — Never Submit These" list plus a 9-row "Conditionally Valid With Chain" table (`SKILL.md:1041-1061`, e.g. "No rate limit + OTP brute force = ATO") and the standing rule: "**N/A hurts your validity ratio. Informative is neutral. Only submit what passes the 7-Question Gate.**" For web3, the equivalent prior-known detection is Q5's audit-report scan and Q7's disclosed-report search.

### 2.15 Report writing standards (shared, with an Immunefi variant)
`agents/report-writer.md:15-22` — six rules: "1. **Never use:** 'could potentially', 'may allow', 'might be possible', 'could lead to'"; "2. **Always prove:** show actual data in the response, not just '200 OK'"; "3. **Impact first:** sentence 1 = what attacker gets, not what the bug is"; "4. **Quantify:** how many users affected … estimated $ value"; "5. **Short:** under 600 words. Triagers skim."; "6. **Human:** write to a person, not a system". Title formula (`report-writer.md:42-44`): "`[Bug Class] in [Exact Endpoint] allows [attacker role] to [impact] [victim scope]`". The Immunefi variant (`report-writer.md:142-169`) requires: "Root cause + affected function + economic impact + attack cost. Include numbers."; PoC section = "Foundry test that runs with: `forge test --match-test test_exploit -vvvv`"; Impact section = "Attacker can drain $[X] from the protocol. Requires $[Y] gas (~$[Z]). Attack is [repeatable / one-time]." Escalation language bank (`report-writer.md:187-192`): "'This requires only a free account — no special privileges.' … 'An attacker can automate this in minutes with a simple loop.'" The web3-auditor agent's finding template (`agents/web3-auditor.md:134-157`) adds CLASS/FUNCTION/SEVERITY/ROOT CAUSE/VULNERABLE CODE/IMPACT/FIX/FOUNDRY POC plus a confidence-tagged decision output ("CONFIDENCE: [HIGH / MEDIUM / LOW] — [reason]").

### 2.16 10 Attacker Questions per external function
`web3/01-foundation.md:37-50` — a per-function interrogation list worth institutionalizing: "1. What if `amount = 0`? … 2. What if I call this function twice in the same block? 3. What if I call this before `initialize()` is called? … 6. What if the token has fee-on-transfer? … 8. What if I pass `type(uint256).max` as a numeric param? 9. Can I combine this with a flash loan? … 10. **Does a sibling function lack the same modifier this function has?**"

### 2.17 Kill-signal culture: 5-Minute Rule + depth-over-breadth
`web3/01-foundation.md:65-74`: "If you've been on the same function for 5 minutes with no clear attack path → **STOP.** Add it to a low-priority list." "Top hunters: 95% fast-reject + 5% deep dives on confirmed leads." "Don't review 10 protocols in one week. Pick ONE. Spend 3-5 days becoming the expert." "The Curve expert found 5 bugs. The 10-protocol tourist found 0."

### 2.18 Defense-study abandonment criteria (ZKsync)
`web3/09-live-hunt-zksync.md:155-159` — explicit exit conditions after 25 vectors failed: "1. After systematically testing top 8 attack vectors (Days 1-2): if all blocked, ROI drops exponentially; 2. If OZ/ToB audited the EXACT codebase version you're reviewing … 4. If encoding, access control, and CEI are all consistently applied with zero exceptions." The hardening patterns observed (CEI everywhere, independent per-contract access control, encoding version discriminators `0x00` vs `0x01`) double as a checklist of *what to look for to kill your own findings* — exactly the kind of negative-evidence methodology most audit repos lack.

### 2.19 Token/DEX-specific authority matrices
`web3/11-solana-token-audit.md:25-30` reduces Solana rug analysis to four authority fields ("Each retained authority = a rug vector": Mint/Freeze/Update/Close with the check `spl-token display <MINT>`), with red flags like "`mint_authority = Some(deployer_pubkey)` after token launch" and kill signals ("Mint authority = None (revoked entirely) … Program deployed with `--final` flag (immutable)"). The closing checklist (`11:472-486`) is a directly reusable audit gate: "Mint authority = None? … No Token-2022 transfer hook? … LP tokens burned (not just locked)? … Top 10 holders < 30% of supply … Pool has > $10K liquidity?" The meme-coin grep blocks in `03-grep-arsenal.md:335-342` map each pattern to a rug class: "`_mint()` callable by owner without MAX_SUPPLY cap → Tier 1 (infinite mint rug)"; "`renounceOwnership` override that doesn't call `_transferOwnership(address(0))` → Tier 1 (fake renounce)". DEX interaction gate (`12-dex-lp-attacks.md:457-478`): "VERIFY price oracle → Spot reserves (bad) vs TWAP (better) vs Chainlink (best)."

### 2.20 Agent-orchestration gates (recon-ranker)
`agents/recon-ranker.md:88-93` — ranking rules that prevent redundant work: "If hunt memory shows this endpoint was tested before, deprioritize (unless the test was >30 days ago)"; "If a pattern from another target matches this tech stack, boost priority"; "GraphQL endpoints are always P1. WebSocket endpoints are always P1. Admin panels behind auth are P2 (need creds)." Its output format always includes a "Kill List (skip these)" section — triage discipline embedded into the recon phase.

---

## 3. Contradictions with Other Methodologies

1. **Severity model: impact-tier ladder vs 3-axis multiplication vs CVSS.** `05-triage-report-examples.md` simultaneously instructs (Q2) "Match your bug to one of these EXACTLY" against the Immunefi impact-tier list (impact-only, Primacy of Impact) *and* (Severity Matrix) "Score = Impact × Likelihood × Exploitability (each 1–3)". Immunefi's actual model is impact-only; likelihood-multiplication can under-rate an easy-but-rare path. Meanwhile `tools/validate.py` scores CVSS 4.0 (macro-vector EQ1–EQ4) and `SKILL.md` ships a CVSS 3.1 quick guide — CVSS is unused by Immunefi for smart-contract bugs. A web3 finding can therefore pass Q2, then receive a CVSS number that disagrees with its impact tier, with no reconciliation rule.

2. **"Admin can do X" gate vs token-audit findings.** Q4 (`05:64`) kills admin-privilege bugs for bounty submissions, but the meme-coin/Solana files treat owner privileges as *the* bug class ("Hidden Mint / Unlimited Supply … 35% of meme coin rugs" in `10-meme-coin-bugs.md:13-14`). Both are correct in their own context (bounty validity vs asset-risk audit), but no file states the context switch explicitly — a naive reader can apply the wrong gate to the wrong deliverable.

3. **Pre-dive hard-kill vs refined soft-kill vs depth-over-breadth.** `web3-auditor.md` says "2+ top-tier audits … → STOP" (hard kill) and "Don't review 10 protocols … Pick ONE" (persistence), while `09-live-hunt-zksync.md:38-40` self-corrects: "Pre-dive should weight audit quality MORE for large protocols … Add 'audit firm tier' as a SOFT kill signal." The chain contains both the old and the refined rule without unifying them.

4. **Evidence requirement mismatch between validator and web3 PoC chain.** `agents/validator.md:28-30` (Q1) demands "a real HTTP request" — "NO: 'Researcher only read code, no confirmed PoC' → KILL Q1" — while the web3 chain's equivalent evidence is the Foundry fork test ("Immunefi requires RUNNABLE code"). If the shared validator agent is invoked on a web3 finding, Q1 as written would kill every valid web3 finding for lacking an HTTP request. The Burp-MCP sections in validator/report-writer/web3-auditor acknowledge the web2 bias only tangentially.

5. **Flash-loan statistics tension.** `04:1121` ranks "Oracle/Price Manipulation 32% … Logic Error 28% … Access Control 19%" of *hacks*, while `02:1105-1109` ranks "Accounting Desync 28% … Access Control 19% … Incomplete Path 17%" of *Immunefi Criticals* and marks Accounting Desync "Flash Loan? No". The two tables coexist without explaining that hack-frequency ≠ bounty-Critical-frequency, which changes which class an auditor should grep first.

6. **CVSS version drift across the repo.** `SKILL.md` (web2 master) and Gate 3 use CVSS 3.1; `tools/validate.py` implements CVSS 4.0; `agents/report-writer.md` teaches CVSS 4.0 vectors. A finding scored in one path can carry an incomparable score in another.

7. **Never-submit list has no web3 analog.** The shared always-rejected list (`SKILL.md:1043`, `validator.md:59-79`) is entirely web2 (missing headers, self-XSS, logout CSRF). The web3 files never produce the equivalent "always rejected on Immunefi" list (e.g., gas-griefing, zero-value transfer spam, admin-key centralization, user error prerequisites), so web3 hunters lack the same instant-kill reference.

---

## 4. Gaps

- **No per-program exclusion cross-check.** Q2 says match impacts "EXACTLY," but there is no tooling or checklist mapping a program's specific exclusions (e.g., "economic attacks excluded," "zero-value transfers out of scope") into a machine-readable gate. `tools/scope_checker.py` handles assets and vuln classes, but the web3 files never feed Immunefi's impact-exclusion lists into it.
- **Duplicate detection is H1-only.** `validate.py` Gate 4 queries Hacktivity/GitHub for web2 programs; there is no Immunefi disclosed-report source, so web3 duplicate/known-issue detection is manual (Q5/Q7 prose only).
- **Severity matrix is skeletal.** The Impact × Likelihood × Exploitability table (`05:112-114`) shows only a corner of the grid and never maps products (1–27) to Critical/High/Medium/Low labels or to the impact-tier list, making it illustrative rather than operational.
- **No economic-viability spreadsheet or formulas.** Q6 demands profit > cost but supplies only two anecdotes; there is no template for flash-loan cost, gas estimates, or TVL-drain simulation. For the repo that claims "83% of successful exploits used flash loans," this is a notable omission.
- **Invariant methodology is thin.** Only three example Echidna invariants are given; there is no systematic invariant-extraction procedure (per protocol type), no Foundry `invariant` test harness config (target contracts, call depth, fail-on-revert), and no guidance on deriving invariants from design docs — a gap relative to competitor methodologies that treat documented-invariant violation as the top finding source.
- **No Solana/PoS-Cairo PoC harness.** Solana and meme-coin files are grep+checklist only; no Anchor test template, no localnet repro harness, no CPI trace tooling — asymmetric with the EVM Foundry depth.
- **PoC cheatcode section is reference, not gate.** The cheatcodes and 18 templates exist, but there is no "required evidence checklist" tying each bug class to the minimal PoC artifacts (logs, before/after balances, assert) beyond the single template.
- **ZK/novel-VM surface acknowledged but uncovered.** `09-live-hunt-zksync.md:161-166` admits "ZK circuits (Rust/RISC-V) — different skillset" and Bootloader Yul as the remaining surfaces, with no skill content for them.
- **No stale-report/knowledge-decay mechanism.** The stats ("2,749 Immunefi reports", "681 hacks") are pinned at build time; nothing tracks new classes (e.g., restaking withdrawals, EIP-7702) except the "2025 new patterns" grep block.

---

## 5. Classification in a Unified Security Skill Taxonomy

| Role | Evidence |
|---|---|
| **Core methodology** | `web3/01-foundation.md` (mindset, recon checklist, 10-point scorecard, attacker questions, kill signals); `web3/02-bug-classes.md` (10-class taxonomy with frequency ordering); `agents/web3-auditor.md` (ordered audit protocol + decision output); the 5-Phase workflow and Phase gates in `SKILL.md`. |
| **Specialized sub-skill** | `web3/10-meme-coin-bugs.md` (8 token rug classes), `web3/11-solana-token-audit.md` (SPL/Token-2022/pump.fun), `web3/12-dex-lp-attacks.md` (sandwich, pool sniping, CL manipulation), `web3/36-solidity-audit-mcp.md` (MCP scanner pipeline). |
| **Reference material** | `web3/05-triage-report-examples.md` (20 paid examples + 3 universal patterns), `web3/06-methodology-research.md` (ToB/SlowMist/ConsenSys/Immunefi/Cyfrin/Lido/Nethermind synthesis), `web3/09-live-hunt-zksync.md` (defense study), `web3/08-ai-tools.md`, common mainnet addresses in `04`. |
| **Tool integration** | `web3/03-grep-arsenal.md` (copy-paste grep blocks), `04-poc-and-foundry.md` (forge templates, `vm.*` cheatcodes, RPC setup), `06` (Slither/Echidna/Medusa/Halmos commands), `web3/36` (MCP), `commands/arsenal.md` + `tools/external_arsenal.sh` (tool inventory gating). |
| **Validation mechanism** | `tools/validate.py` (4 deterministic gates, CVSS 4.0, `validated_finding` vs `scanner_hit`), `tools/scope_checker.py` (anchored allowlist, fail-closed), `agents/validator.md` (PASS/KILL/DOWNGRADE/CHAIN REQUIRED), pre-submission Gate 0–3 checklists in `SKILL.md`. |
| **Judge mechanism** | The 7-Question Gate (`05-triage-report-examples.md` + `validator.md`), the 6 Triager Counter-Questions, the impact-tier severity ladder, the 3-axis severity matrix, kill-signal tables per bug class, and the triager-empathy rule ("read your report as if you're a tired triager at 5pm on a Friday"). |

**Preservation verdict:** The highest-value, most transferable gates are §2.1 (Bug Validation Template), §2.2 (sibling-modifier ONE RULE), §2.3 (self-kill counter-questions), §2.5 (7-Question Gate with Immunefi impact tiers), §2.12–2.13 (deterministic validate.py/scope_checker.py gates), §2.8 (3 universal patterns), and §2.9 (tiered grep triage). These should be adapted verbatim or near-verbatim; the contradictions in §3 (impact-tier vs CVSS, admin-gate context switching, HTTP-vs-Foundry evidence) must be resolved at integration time.






