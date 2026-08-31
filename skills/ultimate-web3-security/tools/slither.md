# Tool Card — Slither

**Run**: `slither . --exclude-dependencies` (add `--filter-paths "test|script|lib"`).

**Questions it answers**: Where are the obvious code-shape risks — unprotected functions, missing `nonReentrant`, uninitialized storage, arbitrary `delegatecall`, reentrancy patterns, unchecked returns, dangerous `tx.origin` usage?

**Evidence it produces**: detector hits with file/line and a rule name; data-flow graphs (e.g., taint from user input to `SSTORE`/`SELFDESTRUCT`); call graphs.

**Blind spots**: no cross-contract semantics (can't know a token is fee-on-transfer); no economic reasoning; no state-sequence reasoning (reentrancy via 3-function chains); detector ≠ exploit — many hits are style-level (dead code, naming); high FP rate on proxy/upgradeable patterns without proper config.

**Usage in the pipeline**: Phase 4 pre-pass. Every hit goes to `leads.md` tagged `[slither:<detector>]`. NEVER report a Slither hit directly — push it through the reasoning protocol. Useful queries: `slither . --print call-graph`, `--print data-dependency` for money-map validation.
