import { describe, expect, test } from "bun:test"
import { Schema } from "effect"
import { EngagementSchema } from "@auditcode/core/engagement/schema"

function baseState(): EngagementSchema.State {
  return {
    id: EngagementSchema.ID.make("art12345"),
    name: "art",
    created_at: "2026-07-21T00:00:00.000Z",
    updated_at: "2026-07-21T00:00:00.000Z",
    scope: { targets: [], excludes: [], notes: "" },
    hosts: {},
    credentials: {},
    flags: [],
    attack_path: [],
    task_tree: [],
    current_phase: "post_exploit",
    mode: "auto",
    notes: [],
  }
}

// A-2 minimal: artifacts[] must round-trip so a recorded reusable weapon (path +
// how to invoke) survives save/load and is visible to sibling agents.
describe("Artifact schema (A-2 minimal)", () => {
  test("State with artifacts[] encode/decode round-trips", () => {
    const state: EngagementSchema.State = {
      ...baseState(),
      artifacts: [
        { id: "art-1", name: "dubbo-cc7", path: "/tmp/r20.sh", type: "exploit", description: "run: /tmp/r20.sh <cmd>", host_ip: "172.50.2.20", created_at: "2026-07-21T00:00:00.000Z" },
        { id: "art-2", name: "loot-passwd", path: "/loot/passwd", type: "loot", created_at: "2026-07-21T00:00:00.000Z" },
      ],
    }
    const encoded = Schema.encodeSync(EngagementSchema.State)(state)
    const decoded = Schema.decodeUnknownSync(EngagementSchema.State)(encoded)
    expect(decoded.artifacts).toHaveLength(2)
    expect(decoded.artifacts?.[0]?.type).toBe("exploit")
    expect(decoded.artifacts?.[0]?.path).toBe("/tmp/r20.sh")
    expect(decoded.artifacts?.[1]?.description).toBeUndefined() // optional
  })

  test("State with no artifacts still decodes (optional field)", () => {
    const decoded = Schema.decodeUnknownSync(EngagementSchema.State)(Schema.encodeSync(EngagementSchema.State)(baseState()))
    expect(decoded.artifacts).toBeUndefined()
  })

  test("invalid artifact type is rejected by the schema", () => {
    const bad = { ...baseState(), artifacts: [{ id: "x", name: "n", path: "/p", type: "banana", created_at: "2026-07-21T00:00:00.000Z" }] }
    expect(() => Schema.decodeUnknownSync(EngagementSchema.State)(bad as unknown)).toThrow()
  })

  test("socks_proxy is a valid live-session type (the enum the alias normalizes to)", () => {
    const s: EngagementSchema.State = {
      ...baseState(),
      live_sessions: [{ id: "s1", session_type: "socks_proxy", host_ip: "172.50.1.18", port: 1080, established_at: "2026-07-21T00:00:00.000Z" }],
    }
    const decoded = Schema.decodeUnknownSync(EngagementSchema.State)(Schema.encodeSync(EngagementSchema.State)(s))
    expect(decoded.live_sessions?.[0]?.session_type).toBe("socks_proxy")
  })
})
