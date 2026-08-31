# Tool Card — Semgrep

**Run**: `semgrep --config <rules-dir> <src>` (custom rules) or `--config auto` for a baseline.

**Questions it answers**: Does the codebase contain this EXACT code shape? (org-specific patterns: "calls `X.transfer` on arbitrary tokens", "reads spot reserves for pricing", "no staleness check after `latestRoundData`", "`initialize` without `initializer` modifier"). Rule = your own detector with machine-enforced reachability.

**Evidence it produces**: rule-id + file/line matches; mechanical — reproducible in CI.

**Blind spots**: syntactic only — it cannot reason about semantics the rule doesn't encode; a rule that fires is a shape match, not a bug (grep-grade evidence); rules rot (false negatives when code shapes evolve); no cross-file data flow (that's CodeQL's job).

**Usage in the pipeline**: Phase 4 — encode the attack-catalog triggers from `skills/evm-deep-audit/references/attack-catalog.md` as rules for THIS audit (targeted hunting), run, and triage every match through the reasoning protocol. Alerts = leads.
