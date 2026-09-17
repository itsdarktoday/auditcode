import { describe, expect, test } from "bun:test"
import { EngagementSchema } from "@auditcode/core/engagement/schema"

describe("Engagement Scoping and Deduplication", () => {
  test("summary deduplicates vulnerabilities shared between state.vulns and host.vulns", () => {
    const vuln1 = {
      id: "AC-1001",
      title: "Reentrancy in withdraw()",
      contract_name: "Vault",
      severity: "critical" as const,
      status: "confirmed" as const,
    }
    const vuln2 = {
      id: "AC-1002",
      title: "Oracle price manipulation",
      contract_name: "Pool",
      severity: "high" as const,
      status: "suspected" as const,
    }

    const state = {
      id: EngagementSchema.ID.make("test1234"),
      name: "test-engagement",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      scope: { targets: ["/projects/my-vault"], excludes: [] },
      contracts: {},
      vulns: {
        "AC-1001": vuln1,
        "AC-1002": vuln2,
      },
      hosts: {
        Vault: {
          ip: "Vault",
          services: [],
          vulns: [vuln1], // duplicate of AC-1001
          access: [],
          notes: [],
        },
      },
      credentials: {},
      flags: [],
      attack_path: [],
      task_tree: [],
      current_phase: "scope_recon" as const,
      mode: "auto" as const,
      notes: [],
    }

    const s = EngagementSchema.summary(state as unknown as EngagementSchema.State)
    // Should NOT double count AC-1001
    expect(s.vulnerabilities_total).toBe(2)
    expect(s.critical).toBe(1)
    expect(s.high).toBe(1)
    expect(s.medium).toBe(0)
  })

  test("summary filters out false_positive, mitigated, and rejected vulns", () => {
    const validVuln = {
      id: "AC-2001",
      title: "Unchecked return value",
      severity: "medium" as const,
      status: "confirmed" as const,
    }
    const fpVuln = {
      id: "AC-2002",
      title: "False positive reentrancy",
      severity: "critical" as const,
      status: "false_positive" as const,
    }
    const mitigatedVuln = {
      id: "AC-2003",
      title: "Fixed overflow",
      severity: "high" as const,
      status: "mitigated" as const,
    }
    const rejectedVuln = {
      id: "AC-2004",
      title: "Disproven by Blue Team",
      severity: "critical" as const,
      status: "suspected" as const,
      critic_review: { verdict: "rejected" as const },
    }

    const state = {
      id: EngagementSchema.ID.make("test5678"),
      name: "filter-test",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      scope: { targets: [], excludes: [] },
      contracts: {},
      vulns: {
        "AC-2001": validVuln,
        "AC-2002": fpVuln,
        "AC-2003": mitigatedVuln,
        "AC-2004": rejectedVuln,
      },
      hosts: {},
      credentials: {},
      flags: [],
      attack_path: [],
      task_tree: [],
      current_phase: "deep_audit" as const,
      mode: "auto" as const,
      notes: [],
    }

    const s = EngagementSchema.summary(state as unknown as EngagementSchema.State)
    expect(s.vulnerabilities_total).toBe(1)
    expect(s.critical).toBe(0) // FP and rejected criticals excluded!
    expect(s.high).toBe(0) // mitigated high excluded!
    expect(s.medium).toBe(1) // only validVuln counted!
  })
})
