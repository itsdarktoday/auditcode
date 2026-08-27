import { describe, expect, test } from "bun:test"
import { Schema } from "effect"
import { EngagementSchema } from "@auditcode/core/engagement/schema"

function baseState(): EngagementSchema.State {
  return {
    id: EngagementSchema.ID.make("test1234"),
    name: "test-engagement",
    created_at: "2026-07-15T00:00:00.000Z",
    updated_at: "2026-07-15T00:00:00.000Z",
    scope: { targets: [], excludes: [], notes: "" },
    hosts: {},
    credentials: {},
    flags: [],
    attack_path: [],
    task_tree: [],
    current_phase: "recon",
    mode: "auto",
    notes: [],
  }
}

function vector(patch: Partial<EngagementSchema.ResolvedVector>): EngagementSchema.ResolvedVector {
  return {
    id: "vec-1",
    timestamp: "2026-07-15T00:00:00.000Z",
    target: "http://localhost:3000/redirect",
    vector: "open-redirect",
    status: "resolved",
    ...patch,
  }
}

describe("ResolvedVector schema", () => {
  test("State encode/decode round-trips resolved_vectors", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [
        vector({ status: "resolved", evidence: "URL is validated, no external redirect possible" }),
        vector({ id: "vec-2", target: "http://localhost:3000/api", vector: "JWT alg-confusion", status: "blocked", revisit_when: "obtain a valid HS256 secret", attempts: 2 }),
      ],
    }
    const encoded = Schema.encodeSync(EngagementSchema.State)(state)
    const decoded = Schema.decodeUnknownSync(EngagementSchema.State)(encoded)
    expect(decoded.resolved_vectors).toHaveLength(2)
    expect(decoded.resolved_vectors?.[0]?.status).toBe("resolved")
    expect(decoded.resolved_vectors?.[1]?.revisit_when).toBe("obtain a valid HS256 secret")
  })

  test("State with no resolved_vectors still decodes (optional field)", () => {
    const encoded = Schema.encodeSync(EngagementSchema.State)(baseState())
    const decoded = Schema.decodeUnknownSync(EngagementSchema.State)(encoded)
    expect(decoded.resolved_vectors).toBeUndefined()
  })
})

describe("toResolvedVectorsContext", () => {
  test("returns undefined when nothing is settled", () => {
    expect(EngagementSchema.toResolvedVectorsContext(baseState())).toBeUndefined()
  })

  test("renders a block and orders resolved/blocked before attempted", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [
        vector({ id: "a", vector: "attempted-thing", status: "attempted" }),
        vector({ id: "r", vector: "dead-end", status: "resolved", evidence: "validated" }),
      ],
    }
    const ctx = EngagementSchema.toResolvedVectorsContext(state)
    expect(ctx).toContain("<resolved-vectors>")
    expect(ctx).toContain("[RESOLVED]")
    expect(ctx).toContain("[ATTEMPTED]")
    // resolved should be listed before attempted (hard "don't retest" first)
    expect(ctx!.indexOf("[RESOLVED]")).toBeLessThan(ctx!.indexOf("[ATTEMPTED]"))
  })

  test("shows attempt count and blocked precondition", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [
        vector({ status: "blocked", revisit_when: "need creds", attempts: 3 }),
      ],
    }
    const ctx = EngagementSchema.toResolvedVectorsContext(state)
    expect(ctx).toContain("x3")
    expect(ctx).toContain("revisit: need creds")
  })

  test("NEW-1: excludes CONFIRMED from the block but counts them in the overflow", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [
        vector({ id: "c", vector: "sqli-confirmed", status: "confirmed" }),
        vector({ id: "r", vector: "dead-end", status: "resolved" }),
      ],
    }
    const ctx = EngagementSchema.toResolvedVectorsContext(state)!
    expect(ctx).toContain("[RESOLVED]")
    expect(ctx).not.toContain("[CONFIRMED]")
    expect(ctx).not.toContain("sqli-confirmed")
    expect(ctx).toContain("+1 more") // the confirmed one is still accounted for
  })

  test("NEW-1: returns undefined when only confirmed vectors exist", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [vector({ status: "confirmed" }), vector({ id: "c2", status: "confirmed" })],
    }
    expect(EngagementSchema.toResolvedVectorsContext(state)).toBeUndefined()
  })

  test("NEW-1: clips long evidence in the block", () => {
    const long = "x".repeat(300)
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [vector({ status: "resolved", evidence: long })],
    }
    const ctx = EngagementSchema.toResolvedVectorsContext(state)!
    expect(ctx).toContain("…")
    expect(ctx).not.toContain(long) // full evidence is not inlined
  })

  test("surfaces FAILED sub-attempts for in-progress vectors, not for resolved ones", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [
        vector({
          id: "grind",
          target: "192.0.2.20:8080",
          vector: "Dubbo CVE-2019-17564 Java-deser RCE",
          status: "attempted",
          attempt_log: [
            { technique: "gadget CommonsCollections6", outcome: "failed", detail: "ClassNotFound on target classpath" },
            { technique: "gadget ROME", outcome: "success", detail: "root shell" },
          ],
        }),
        vector({
          id: "done",
          status: "resolved",
          attempt_log: [{ technique: "payload X", outcome: "failed", detail: "validated input" }],
        }),
      ],
    }
    const ctx = EngagementSchema.toResolvedVectorsContext(state)!
    // in-progress vector surfaces the failed technique with a don't-repeat marker
    expect(ctx).toContain("gadget CommonsCollections6")
    expect(ctx).toContain("don't repeat")
    // the successful sub-attempt is NOT listed as a dead end
    expect(ctx).not.toContain("gadget ROME")
    // a resolved vector's attempt log is not expanded (one-liner suffices)
    expect(ctx).not.toContain("payload X")
  })
})

describe("VectorAttempt / attempt_log schema", () => {
  test("round-trips attempt_log through encode/decode", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      resolved_vectors: [
        vector({
          status: "attempted",
          attempt_log: [
            { technique: "gadget CC6", outcome: "failed", detail: "ClassNotFound", timestamp: "2026-07-16T09:10:00.000Z" },
          ],
        }),
      ],
    }
    const encoded = Schema.encodeSync(EngagementSchema.State)(state)
    const decoded = Schema.decodeUnknownSync(EngagementSchema.State)(encoded)
    expect(decoded.resolved_vectors?.[0]?.attempt_log?.[0]?.technique).toBe("gadget CC6")
    expect(decoded.resolved_vectors?.[0]?.attempt_log?.[0]?.outcome).toBe("failed")
  })
})
