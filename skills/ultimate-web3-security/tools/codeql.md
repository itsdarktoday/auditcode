# Tool Card — CodeQL

**Run**: requires DB creation (`codeql database create`) + queries (`.ql`). Use community Solidity query packs when available.

**Questions it answers**: cross-file, interprocedural questions: does attacker-controlled data reach this `SSTORE`/external call? (taint tracking) · which callers can reach this unguarded function? (access-path analysis) · where does this variable flow?

**Evidence it produces**: a data-flow path (source → sink) with intermediate steps — stronger evidence than pattern matches.

**Blind spots**: setup cost (DB + query tuning) is high relative to value for small audits; no economic/semantic reasoning (it doesn't know the token is rebasing); query packs for Solidity are less mature than for JS/Java; false negatives if the taint model misses a wrapper (e.g., assembly, proxies).

**Usage in the pipeline**: Phase 4 for `--deep` audits on large codebases (≥10k SLOC) — use for: user-input → fund-flow taint, delegatecall target taint, access-path queries for admin-only functions. Alerts = leads with attached paths.
