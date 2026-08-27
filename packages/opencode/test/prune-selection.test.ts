import { describe, expect, test } from "bun:test"
import { selectPrunableParts, PRUNE_PROTECT } from "@/session/compaction"
import type { SessionV1 } from "@auditcode/core/v1/session"

// A-5 regression guard: prune-to-ref must never eat the ACTIVE context. These
// tests lock the depth-protection invariants of the selection pass — the exact
// place a compaction change could silently drop the vector the exploit depends on.
// A predictable estimate (output length) + a small protect budget make the token
// math deterministic; protectTurns=2 matches production.

const OPTS = { protectTokens: 100, protectTurns: 2, estimate: (o: unknown) => String(o).length }

let partCounter = 0
function toolPart(tool: string, output: string, opts: { compacted?: boolean } = {}): SessionV1.ToolPart {
  return {
    type: "tool",
    tool,
    id: `prt_${tool}_${partCounter++}`,
    state: { status: "completed", output, time: { start: 0, end: 1, ...(opts.compacted ? { compacted: 2 } : {}) } },
  } as unknown as SessionV1.ToolPart
}
function msg(role: "user" | "assistant", parts: SessionV1.ToolPart[], opts: { summary?: boolean } = {}): SessionV1.WithParts {
  return { info: { role, ...(opts.summary ? { summary: "s" } : {}) }, parts } as unknown as SessionV1.WithParts
}
const ids = (parts: SessionV1.ToolPart[]) => parts.map((p) => (p as unknown as { id: string }).id)

describe("selectPrunableParts (A-5 depth protection)", () => {
  test("never prunes tool output inside the most recent protectTurns turns", () => {
    // Both tool parts sit within the last 2 turns → fully protected regardless of size.
    const msgs = [
      msg("user", []),
      msg("assistant", [toolPart("bash", "X".repeat(500))]),
      msg("user", []),
      msg("assistant", [toolPart("bash", "Y".repeat(500))]),
    ]
    const { toPrune } = selectPrunableParts(msgs, OPTS)
    expect(toPrune.length).toBe(0)
  })

  test("never prunes a PROTECTED tool (e.g. skill) even when old and over budget", () => {
    const skill = toolPart("skill", "S".repeat(500))
    const bash = toolPart("bash", "B".repeat(500))
    const msgs = [msg("assistant", [skill, bash]), msg("user", []), msg("user", [])]
    const { toPrune } = selectPrunableParts(msgs, OPTS)
    expect(ids(toPrune)).toContain(ids([bash])[0])
    expect(ids(toPrune)).not.toContain(ids([skill])[0]) // skill body stays
  })

  test("keeps the most-recent protectTokens worth of tool output verbatim", () => {
    const older = toolPart("bash", "O".repeat(80))
    const recent = toolPart("bash", "R".repeat(80)) // 80 <= 100 budget → protected
    const msgs = [
      msg("assistant", [older]),
      msg("assistant", [recent]),
      msg("user", []),
      msg("user", []),
    ]
    const { toPrune, prunedTokens, scannedTokens } = selectPrunableParts(msgs, OPTS)
    expect(ids(toPrune)).toEqual(ids([older])) // only the part beyond the budget
    expect(ids(toPrune)).not.toContain(ids([recent])[0])
    expect(prunedTokens).toBe(80)
    expect(scannedTokens).toBe(160)
  })

  test("stops at a summary boundary — never prunes across a compacted summary", () => {
    const behind = toolPart("bash", "H".repeat(500)) // older than the summary
    const after = toolPart("bash", "A".repeat(500))
    const msgs = [
      msg("assistant", [behind]),
      msg("assistant", [], { summary: true }),
      msg("assistant", [after]),
      msg("user", []),
      msg("user", []),
    ]
    const { toPrune } = selectPrunableParts(msgs, OPTS)
    expect(ids(toPrune)).toEqual(ids([after]))
    expect(ids(toPrune)).not.toContain(ids([behind])[0]) // behind the summary = untouched
  })

  test("stops at an already-compacted part (does not cross it)", () => {
    const behind = toolPart("bash", "H".repeat(500))
    const compacted = toolPart("bash", "C".repeat(500), { compacted: true })
    const live = toolPart("bash", "L".repeat(500))
    const msgs = [
      msg("assistant", [behind]),
      msg("assistant", [compacted]),
      msg("assistant", [live]),
      msg("user", []),
      msg("user", []),
    ]
    const { toPrune } = selectPrunableParts(msgs, OPTS)
    expect(ids(toPrune)).toEqual(ids([live]))
    expect(ids(toPrune)).not.toContain(ids([compacted])[0])
    expect(ids(toPrune)).not.toContain(ids([behind])[0])
  })

  test("production budget PRUNE_PROTECT protects a realistically-sized tail", () => {
    // With the real 40k-token budget, a handful of normal tool outputs never prune.
    const parts = Array.from({ length: 5 }, (_, i) => toolPart("bash", "z".repeat(1000)))
    const msgs = [msg("assistant", parts), msg("user", []), msg("user", [])]
    const { toPrune } = selectPrunableParts(msgs, { protectTokens: PRUNE_PROTECT, protectTurns: 2, estimate: (o) => String(o).length })
    expect(toPrune.length).toBe(0) // 5*1000 chars << 40k budget
  })
})
