import { describe, expect, test } from "bun:test"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { buildCappedOutput, OUTPUT_HARD_CAP } from "@/session/small-model"

// TOKEN CHECK (deterministic, no live target): the context/token work only helps
// if per-turn context is BOUNDED — i.e. a 30x-larger engagement state must NOT
// produce a 30x-larger context block. These tests measure the pure formatters on
// a small vs a deliberately-oversized state and assert the caps hold, and quantify
// the C-4 output cap on a realistic 50KB scan dump. Sizes are printed so the
// saving is visible, not just asserted.

function baseState(): EngagementSchema.State {
  return {
    id: EngagementSchema.ID.make("tok12345"),
    name: "tok",
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

function host(ip: string): EngagementSchema.Host {
  return { ip, services: [], vulns: [], access: [], notes: [] } as unknown as EngagementSchema.Host
}
function vector(i: number): EngagementSchema.ResolvedVector {
  return {
    id: `vec-${i}`,
    timestamp: "2026-07-15T00:00:00.000Z",
    target: `10.0.0.${i % 255}:8080`,
    vector: `vector-${i}`,
    status: i % 2 ? "resolved" : "blocked",
    // long evidence to prove the clip: a formatter that dumps this verbatim balloons
    evidence: "E".repeat(2000),
    revisit_when: "R".repeat(2000),
  }
}

function withHosts(n: number): EngagementSchema.State {
  const s = baseState()
  const hosts: Record<string, EngagementSchema.Host> = {}
  for (let i = 0; i < n; i++) hosts[`10.0.0.${i}`] = host(`10.0.0.${i}`)
  return { ...s, hosts }
}
function withVectors(n: number): EngagementSchema.State {
  return { ...baseState(), resolved_vectors: Array.from({ length: n }, (_, i) => vector(i)) }
}

describe("context is bounded, not proportional to state size (C-1 / NEW-1 / compact caps)", () => {
  test("toCompactContext: 100 hosts is NOT ~33x a 3-host context (host cap holds)", () => {
    const small = EngagementSchema.toCompactContext(withHosts(3))
    const huge = EngagementSchema.toCompactContext(withHosts(100))
    console.log(`\n[toCompactContext] 3 hosts: ${small.length} chars | 100 hosts: ${huge.length} chars | ratio ${(huge.length / small.length).toFixed(1)}x for 33x the state`)
    // Uncapped this would be ~33x; the maxHosts=20 cap keeps it well under 10x.
    expect(huge.length).toBeLessThan(small.length * 10)
    expect(huge).toContain("hosts_omitted") // omission is surfaced (80), not silently dropped
  })

  test("toResolvedVectorsContext: 200 long vectors render bounded (max 30 + evidence clip)", () => {
    const ctx = EngagementSchema.toResolvedVectorsContext(withVectors(200))!
    const rawIfUnclipped = 200 * 4000 // 200 vectors * (2000 evidence + 2000 revisit)
    console.log(`[toResolvedVectorsContext] 200 vectors (~${(rawIfUnclipped / 1000).toFixed(0)}KB raw): ${ctx.length} chars rendered`)
    expect(ctx.length).toBeLessThan(rawIfUnclipped / 5) // clip + max-30 cap → a fraction of raw
    // no single evidence blob rides in full
    expect(ctx).not.toContain("E".repeat(2000))
  })

  test("default cap constants are the documented, sane values", () => {
    expect(EngagementSchema.RESOLVED_VECTORS_MAX).toBeGreaterThan(0)
    expect(OUTPUT_HARD_CAP).toBe(16000)
  })
})

describe("C-4 output cap quantified on a realistic scan dump", () => {
  test("a 50KB dump enters the transcript at ~16KB, full text kept by ref", () => {
    const dump = "open port line\n".repeat(3500) // ~52KB, like a big /24 nmap/nuclei dump
    expect(dump.length).toBeGreaterThan(50_000)
    const { output, metadataPatch } = buildCappedOutput(dump, "/refs/scan-abc")
    const saved = dump.length - output.length
    console.log(`[C-4] raw ${dump.length} bytes -> transcript ${output.length} bytes (saved ${saved}, ${((saved / dump.length) * 100).toFixed(0)}% off the hot path); full text at ${metadataPatch.outputPath}`)
    expect(output.length).toBeLessThan(dump.length / 2) // >50% off the transcript
    expect(output.slice(0, OUTPUT_HARD_CAP)).toBe(dump.slice(0, OUTPUT_HARD_CAP)) // head intact
    expect(metadataPatch.outputPath).toBe("/refs/scan-abc") // retrievable
  })
})
