import { describe, expect, test } from "bun:test"
import { EngagementSchema } from "@auditcode/core/engagement/schema"

const { deriveConfidence } = EngagementSchema

describe("deriveConfidence (I-3)", () => {
  test("is NOT driven by severity — same evidence yields same confidence regardless of severity", () => {
    const item = { tool: "nuclei", verification_status: "unverified" as const }
    const a = deriveConfidence({ status: "confirmed", evidence_items: [item] })
    // severity is not even an input; a single unverified scanner match is moderate, not 0.8
    expect(a).toBeLessThan(0.8)
    expect(a).toBeGreaterThanOrEqual(0.5)
  })

  test("a verified evidence item dominates -> high", () => {
    expect(
      deriveConfidence({ status: "suspected", evidence_items: [{ tool: "nuclei", verification_status: "verified" }] }),
    ).toBe(0.95)
  })

  test("all-false-positive -> low", () => {
    expect(
      deriveConfidence({ status: "confirmed", evidence_items: [{ tool: "x", verification_status: "false_positive" }] }),
    ).toBe(0.1)
  })

  test("independent tools corroborating raises confidence", () => {
    const one = deriveConfidence({ status: "confirmed", evidence_items: [{ tool: "nuclei" }] })
    const two = deriveConfidence({
      status: "confirmed",
      evidence_items: [{ tool: "nuclei" }, { tool: "sqlmap" }],
    })
    expect(two).toBeGreaterThan(one)
  })

  test("exploited > confirmed > suspected", () => {
    const ev = [{ tool: "nuclei", verification_status: "unverified" as const }]
    const exploited = deriveConfidence({ status: "exploited", evidence_items: ev })
    const confirmed = deriveConfidence({ status: "confirmed", evidence_items: ev })
    const suspected = deriveConfidence({ status: "suspected", evidence_items: ev })
    expect(exploited).toBeGreaterThan(confirmed)
    expect(confirmed).toBeGreaterThan(suspected)
  })

  test("clamps to [0.1, 0.95]", () => {
    const hi = deriveConfidence({
      status: "exploited",
      evidence_items: [{ tool: "a" }, { tool: "b" }, { tool: "c" }],
    })
    expect(hi).toBeLessThanOrEqual(0.95)
    expect(hi).toBeGreaterThanOrEqual(0.1)
  })
})
