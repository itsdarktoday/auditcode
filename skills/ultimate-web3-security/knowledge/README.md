# Knowledge / Pattern Memory

Reusable vulnerability-pattern library. Phase 12 of the pipeline writes here; Phase 1.3 (prior-art) and Phase 4 (lens dispatch) read from here.

## Pattern schema

Every pattern file under `patterns/<chain>/<pattern-name>.md`:

```
# <pattern-name> (<chain>)

root cause:          what the code author got wrong (one line)
protocol type:       vault / lending / DEX / bridge / staking / auction / perp / ...
affected architecture: (shares accounting, proxy storage, keeper liquidation, ...)
attack preconditions: (what state/capability the attacker needs)
invariant violated:  the INV form ("totalX == Σ userX", "index never decreases")
exploit pattern:     the concrete attack sequence
detection strategy:  code shapes / triggers / tools that catch it
false-positive indicators: when similar code is actually safe
example PoC:         pointer to a PoC (audit dir path) or "none yet"
```

Rules:

- One root-cause structure per file. Variants live in the same file.
- ≤60 lines. Cite a real finding or PoC when possible — no invented examples.
- Patterns are hypotheses, not verdicts: similar code is NOT automatically vulnerable. A pattern match only earns a closer look.

## Index

`index.md` maps trigger keywords → pattern files, grouped by chain and family. Phase 1.3 consults it to know which patterns are relevant to the protocol type; Phase 4 lens dispatch loads the files when their triggers fire.

## Maintenance

- Only Phase 12 writes here: validated findings, plus kills whose FP indicators generalize.
- Merge new variants into existing family files rather than creating duplicates.
- If a pattern produced a false alarm during this audit, update its false-positive indicators.
