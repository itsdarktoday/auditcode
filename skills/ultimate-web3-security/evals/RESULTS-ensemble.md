# RESULTS — ensemble-judge simulation (2026-08-13)

Simulation of `agents/ensemble-judge.md` on two external candidates. Honest label: **same-model ensemble** (context-independence only, not model-diversity — this runtime exposes one model family; the template requires diversity when available).

## X10 (cpi-bridge-vuln-1) — candidate: unvalidated CPI target

- **Judge A** (account-model lens, fresh derivation from code only): `bridge_program: AccountInfo` unconstrained → CPI target program id never validated → attacker-supplied program substitutes transfer semantics. CONFIRM, HIGH.
- **Judge B** (economic/impact lens, independent pass): source `Account<TokenAccount>` validates type but not ownership; authority Signer unbound to source; exploitability depends on source holding third-party funds (state prerequisite in the real bridge deployment). CONFIRM with prerequisite caveat, confidence 90.
- **Aggregation**: 2/2 CONFIRM → VALID; confidence = min = 90; severity HIGH; caveat attached (deployment prerequisite recorded).

## X13 (cpi-bridge-safe-1) — candidate: any bridge-program validation finding

- **Judge A**: source has `has_one = authority` + authority is Signer → source cannot be swapped away from the authority's own account; transfers of the authority's own funds to an arbitrary dest are authorized behavior. KILL (no victim).
- **Judge B**: same derivation independently; the unconstrained `bridge_program` remains a smell but has no reachable victim given the authority binding. KILL.
- **Aggregation**: unanimous KILL → FALSE POSITIVE / benign confirmed. (Matches external ground truth: expected_findings = [].)

## Outcome
The protocol resolves both directions correctly and forces prerequisite caveats into the record (X10's deployment precondition, X13's smell-without-victim). Zero false verdicts in this simulation; aggregation rules exercised: 2/2 confirm and unanimous kill.
