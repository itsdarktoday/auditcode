import { describe, expect, test } from "bun:test"
import { toVectorLedger } from "../src/engagement/schema"

// #1 vector-ledger — the coordinator's compact strategic board (pure render).
const state: any = {
  hosts: {
    "10.0.0.1": {
      ip: "10.0.0.1",
      hostname: "react",
      services: [{ port: 3000, service: "http", state: "open" }],
      vulns: [],
      access: [{ access_type: "rce", username: "root", level: "root" }],
    },
    "10.0.0.2": {
      ip: "10.0.0.2",
      services: [{ port: 8080, service: "http", state: "open" }],
      vulns: [{ title: "Dubbo deser RCE", status: "confirmed", severity: "critical" }],
      access: [],
    },
    "10.0.0.3": {
      ip: "10.0.0.3",
      services: [
        { port: 80, service: "http", state: "open" },
        { port: 445, service: "smb", state: "open" },
      ],
      vulns: [{ title: "maybe LFI", status: "suspected", confidence: 0.4 }],
      access: [],
    },
  },
  resolved_vectors: [
    { id: "v1", timestamp: "t", target: "10.0.0.4:6379", vector: "redis unauth", status: "resolved" },
    { id: "v2", timestamp: "t", target: "10.0.0.5:80", vector: "still probing", status: "attempted" },
  ],
}

describe("#1 toVectorLedger", () => {
  test("renders status, HOT confirmed, suspected, untried, DEAD, and per-host signal", () => {
    const out = toVectorLedger(state, [
      { timestamp: "t", action: "add_access", entity_type: "access", entity_id: "10.0.0.1", summary: "root on .1" },
    ])!
    expect(out).toContain("10.0.0.1")
    expect(out).toContain("OWNED-root")
    expect(out).toContain("⚡signal") // recent change touched .1
    expect(out).toContain("! confirmed — Dubbo deser RCE") // HOT → finish/escalate
    expect(out).toContain("? suspected — maybe LFI")
    expect(out).toContain("· untried:") // .3 has open services, no access
    expect(out).toContain("DEAD")
    expect(out).toContain("redis unauth")
    expect(out).not.toContain("still probing") // 'attempted' is NOT dead — omit from DEAD list
  })

  test("no signal when recent changes don't touch a host", () => {
    const out = toVectorLedger(state, [])!
    expect(out).not.toContain("⚡signal")
  })

  test("empty hosts -> undefined", () => {
    expect(toVectorLedger({ hosts: {} } as any)).toBeUndefined()
  })
})
