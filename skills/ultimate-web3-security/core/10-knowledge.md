# Phase 12 — Knowledge Memory

Goal: learn reusable patterns from this audit so future audits get better. Output: files under `{SKILL_DIR}/knowledge/`.

## 12.1 Extract patterns

For each **validated finding** (and each instructive kill whose FP indicator generalizes), fill the pattern schema from `knowledge/README.md`:

```
pattern
├── root cause
├── protocol type
├── affected architecture
├── attack preconditions
├── invariant violated
├── exploit pattern
├── detection strategy
├── false-positive indicators
└── example PoC (pointer)
```

Write to `knowledge/patterns/<chain>/<pattern-name>.md`. Rules:

- Only add validated findings, and kills that generalize (FP indicators).
- Keep each pattern ≤ 60 lines. If a pattern file already exists for the family, merge into it instead of creating a duplicate; only create a new file for a genuinely distinct structure.
- Store PoC code in the audit dir; the pattern file points at it.

## 12.2 Update the index

`knowledge/index.md`: pattern → trigger keywords → file, sorted by chain + family. This is what future audits consult in Phase 1.3 (prior-art) and Phase 4 lens dispatch.

## 12.3 Retrospective

Append one paragraph to `{AUDIT_DIR}/retrospective.md`: what worked, what was missed, which lens caught the top finding, which tools produced noise vs signal, what to do differently next time.

## Exit gate

Patterns extracted (or explicit "nothing new to add"); index consistent with files on disk.
