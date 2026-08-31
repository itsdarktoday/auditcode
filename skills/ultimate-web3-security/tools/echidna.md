# Tool Card — Echidna

**Run**: `echidna . --contract FuzzTester --config echidna.yaml` (after `{SKILL_DIR}/skills/fuzz-harness` scaffold).

**Questions it answers**: Does ANY reachable sequence of calls break this property? (stateful fuzzing: it explores sequences, not just inputs). Fast iteration on hypothesis "can invariant X be broken?".

**Evidence it produces**: a minimized call sequence that violates the property (shrinkable to near-minimal), plus coverage data.

**Blind spots**: sequence space explodes — coverage < 100% means unexplored paths (it proves violations exist, never absence); struggles with timestamp-dependent logic unless you model time; bad at access-control bugs (needs many actors); harness quality dominates results — bad clamps hide bugs.

**Usage in the pipeline**: Phase 4/6 for invariant-class hypotheses. Time-box 15–30 min per property. Triaged violations → leads, then the full pipeline.
