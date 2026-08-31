# Evals — measuring the skill, not the marketing

The pipeline's quality claims must be backed by measurement. This directory contains the benchmark corpora and the run protocol.

## Corpora

- **`corpus/`** — internal fixtures (self-authored, planted bugs): 8 vulnerable + 3 clean, 4 executable PoCs. Fast regression gate.
- **`external/fixtures/`** — externally-authored fixtures under neutral IDs (X01–X18): 11 vulnerable (real historical hacks: bZx $8M, Cream $130M, Harvest $34M, Inverse $1.2M, Rari $10M, Cashio $52M — digger-determsec reproducers with rekt.news citations; SUIZERO Move vaults) + 7 benign trap cases. Ground truth sealed in `external/fixtures/ground-truth/`; `MAPPING.md` consulted only at scoring.
- **`RESULTS.md` / `RESULTS-external.md` / `RESULTS-ensemble.md`** — measured numbers of the latest runs.

## Protocol

1. For each fixture run the pipeline-lite: recon → money map + invariants → lenses (chain sub-skill + `knowledge/patterns/`) → hypotheses → judge gates → verdict + severity + confidence + evidence level.
2. Evidence levels: **PoC** (executable forge test) > **trace** (complete unbroken attacker→harm path) > **lead** (incomplete path).
3. External fixtures: audit under neutral IDs FIRST; open ground truth only at scoring. Copy new fixtures with neutral IDs and append to MAPPING.md only after scoring.
4. Compute TP/FN/FP/TN, precision, recall. Recompute after every skill change (regression gate). A failing fixture = methodology change required — fix the skill (patterns, lenses, judge), not the score.
5. CRITICAL/HIGH verdicts may additionally run the ensemble judge (`agents/ensemble-judge.md`); record aggregation.

## Measured baseline (2026-08-13)

- Internal: 8/8 precision, 8/8 recall (4 PoC-level).
- External: 11/11 precision, 11/11 recall (7/7 benign cleared).
- Combined (29 fixtures): **precision 100%, recall 100%, 0 FPs**.
- Ensemble simulation: 2/2 correct verdicts, aggregation rules exercised both directions.

## Remaining limits (stated honestly)

- External evidence is trace-level (Solana/Move toolchains unavailable here; EVM reproducers are excerpts).
- All fixtures are small reproducers; multi-contract live protocols remain the untested frontier.
- Same-model ensemble until a multi-model runtime is available.

