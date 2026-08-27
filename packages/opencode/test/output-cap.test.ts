import { describe, expect, test } from "bun:test"
import { shouldCapOutput, buildCappedOutput, OUTPUT_HARD_CAP } from "@/session/small-model"

// C-4 regression guard: the universal output cap must (a) only fire on large,
// unhandled string outputs, (b) NEVER double-cap something a precision path
// already shaped, and (c) preserve the head verbatim + keep the full text
// retrievable by ref. These are the invariants that protect against silent
// information loss — the whole point of C-4.

describe("shouldCapOutput (C-4 predicate)", () => {
  const big = "x".repeat(OUTPUT_HARD_CAP + 1)
  const small = "x".repeat(OUTPUT_HARD_CAP - 1)

  test("does NOT cap output at or below the cap", () => {
    expect(shouldCapOutput(small, undefined)).toBe(false)
    expect(shouldCapOutput("x".repeat(OUTPUT_HARD_CAP), undefined)).toBe(false) // boundary: == cap stays
  })

  test("caps a large, unhandled string output", () => {
    expect(shouldCapOutput(big, undefined)).toBe(true)
    expect(shouldCapOutput(big, {})).toBe(true)
  })

  test("does NOT cap non-string output (never coerces)", () => {
    expect(shouldCapOutput({ some: "object" } as unknown, undefined)).toBe(false)
    expect(shouldCapOutput(undefined, undefined)).toBe(false)
    expect(shouldCapOutput(12345 as unknown, undefined)).toBe(false)
  })

  test("does NOT double-cap output a precision path already handled", () => {
    // A parser/read that summarized, truncated, or ref'd its own output must be
    // left alone — re-capping would clip an already-shaped result.
    expect(shouldCapOutput(big, { summarized: true })).toBe(false)
    expect(shouldCapOutput(big, { truncated: true })).toBe(false)
    expect(shouldCapOutput(big, { outputPath: "/refs/abc" })).toBe(false)
  })

  test("a falsy/wrong-typed handled-flag does NOT suppress the cap", () => {
    expect(shouldCapOutput(big, { truncated: false })).toBe(true)
    expect(shouldCapOutput(big, { summarized: "yes" })).toBe(true) // only === true suppresses
    expect(shouldCapOutput(big, { outputPath: 123 })).toBe(true) // only a string ref suppresses
  })
})

describe("buildCappedOutput (C-4 builder)", () => {
  const raw = Array.from({ length: OUTPUT_HARD_CAP + 5000 }, (_, i) => String(i % 10)).join("")

  test("preserves the first cap characters VERBATIM (no head loss)", () => {
    const { output } = buildCappedOutput(raw, "/refs/xyz")
    expect(output.slice(0, OUTPUT_HARD_CAP)).toBe(raw.slice(0, OUTPUT_HARD_CAP))
  })

  test("states the true total byte count and points to the ref", () => {
    const { output, metadataPatch } = buildCappedOutput(raw, "/refs/xyz")
    expect(output).toContain(`${raw.length} bytes total`)
    expect(output).toContain("/refs/xyz")
    expect(metadataPatch.truncated).toBe(true)
    expect(metadataPatch.original_bytes).toBe(raw.length)
    expect(metadataPatch.outputPath).toBe("/refs/xyz")
  })

  test("degrades gracefully when the ref write failed (no ref, but still honest)", () => {
    const { output, metadataPatch } = buildCappedOutput(raw, undefined)
    expect(output.slice(0, OUTPUT_HARD_CAP)).toBe(raw.slice(0, OUTPUT_HARD_CAP)) // head still intact
    expect(output).toContain(`${raw.length} bytes total`)
    expect(output).not.toContain("Full output saved to")
    expect(metadataPatch.truncated).toBe(true)
    expect("outputPath" in metadataPatch).toBe(false) // no phantom ref
  })

  test("the transcript copy is smaller than raw but keeps the retrieval pointer", () => {
    const { output } = buildCappedOutput(raw, "/refs/xyz")
    expect(output.length).toBeLessThan(raw.length)
    expect(output.length).toBeGreaterThanOrEqual(OUTPUT_HARD_CAP) // head is fully kept
  })
})
