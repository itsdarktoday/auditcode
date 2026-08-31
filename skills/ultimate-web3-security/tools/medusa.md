# Tool Card — Medusa

**Run**: `medusa fuzz` (uses `medusa.json` from the fuzz harness scaffold).

**Questions it answers**: same as Echidna (does a sequence break the property?) but with parallel workers, longer campaigns, and better coverage reporting per contract.

**Evidence it produces**: corpus + call sequences per violation; per-contract coverage reports.

**Blind spots**: same sequence-space limits; coverage deflation when the project builds with `via_ir = true` (Yul optimizer merges branches — set a `[profile.fuzz]` with `via_ir = false` or lower targets ~15%); heavier setup than Echidna.

**Usage in the pipeline**: the long-campaign variant after a promising Echidna run; coverage reports feed the "unexplored paths" honesty note in the final report. Default choice in fuzz-harness when available.
