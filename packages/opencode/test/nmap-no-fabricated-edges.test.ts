import { describe, expect, test } from "bun:test"
import { join } from "node:path"
import { readFileSync } from "node:fs"

// I-2 regression guard: nmap_parse must NEVER synthesize relationship edges.
// Co-appearing in one scan means the SCANNER reached each host, not that the
// hosts reach each other; fabricating all-pairs REACHABLE_FROM poisoned
// attack_path_suggest (Dijkstra/Yen over invented edges). Reachability is
// recorded ONLY from observed evidence elsewhere (cme AUTHENTICATES_TO, explicit
// state_update, bloodhound). This test fails if edge-fabrication is reintroduced.
//
// It's a source-invariant guard (not behavioral) on purpose: the fix is the
// ABSENCE of a code path, and the cheapest faithful check is "that code path
// stays absent" — no engagement-store harness, fully deterministic.

const SRC = readFileSync(join(import.meta.dir, "../src/tool/nmap-parse.ts"), "utf8")

// Strip line comments so the explanatory NOTE (which legitimately names
// REACHABLE_FROM / add_relationship) doesn't trip the guard — we only inspect
// executable code.
const CODE = SRC.split("\n")
  .map((l) => {
    const i = l.indexOf("//")
    return i >= 0 ? l.slice(0, i) : l
  })
  .join("\n")

describe("nmap_parse fabricates no relationship edges (I-2)", () => {
  test("no REACHABLE_FROM token in executable code (only in comments)", () => {
    expect(CODE).not.toContain("REACHABLE_FROM")
  })

  test("no relationship-creation call in nmap_parse", () => {
    expect(CODE).not.toMatch(/addRelationship\s*\(/)
    expect(CODE).not.toMatch(/add_relationship/)
    expect(CODE).not.toMatch(/relationships\s*\.\s*push/)
  })

  test("the explanatory NOTE is still present (documents the deliberate omission)", () => {
    // Guards against someone deleting the rationale and later 'helpfully' re-adding edges.
    expect(SRC).toContain("do NOT synthesize REACHABLE_FROM")
  })
})
