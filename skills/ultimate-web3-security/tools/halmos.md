# Tool Card — Halmos

**Run**: `halmos --function <fn> --solver-timeout-ms 10000` (bounded symbolic execution).

**Questions it answers**: For a SPECIFIC function with small, bounded state, does a concrete input exist that makes the assertion fail? (e.g., rounding math: can `sharesOut == 0` for `amount > 0`? can exchange rate decrease?).

**Evidence it produces**: a symbolic counterexample (concrete inputs) when the assertion is violated, or proof that none exists within the bounded model.

**Blind spots**: path explosion — only works on small functions/math units; no external-call semantics (mocks everything); no multi-contract state sequences; solver timeouts leave "unknown" answers, which prove nothing.

**Usage in the pipeline**: Phase 4/6 for math-heavy single-function invariants (rounding, exchange rates, fee splits) extracted as `assert`ions. A counterexample → lead with concrete inputs; timeout → note as untested, not as safe.
