import * as nodeFs from "node:fs"
import * as nodePath from "node:path"
import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import DESCRIPTION from "./report-gen.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  format: Schema.optional(Schema.Literals(["markdown", "json"])).annotate({
    description: "Output format (default: markdown)",
  }),
  sections: Schema.optional(Schema.Array(Schema.String)).annotate({
    description:
      "Sections to include: executive_summary, scope, architecture, invariants, findings, recommendations. Default: all.",
  }),
  output_path: Schema.optional(Schema.String).annotate({
    description: "File path to write report. If omitted, returns as tool output.",
  }),
})

function severityOrder(s?: string): number {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, gas: 4, info: 5 }
  return order[s ?? "medium"] ?? 6
}

function generateExecutiveSummary(state: EngagementSchema.State): string {
  const s = EngagementSchema.summary(state)
  const lines: string[] = []

  lines.push("# Smart Contract Security Assessment Report")
  lines.push("")
  lines.push(`**Engagement / Protocol**: ${state.name}`)
  lines.push(`**Assessment Date**: ${new Date(state.created_at).toLocaleDateString()} — ${new Date(state.updated_at).toLocaleDateString()}`)
  lines.push(`**Audit Framework**: AuditCode Autonomous Multi-Agent Harness`)
  lines.push(`**Phase**: ${state.current_phase}`)
  lines.push("")
  lines.push("## Executive Summary")
  lines.push("")
  lines.push("This security assessment report documents vulnerabilities, economic risks, invariant violations, and architecture flaws discovered during the comprehensive smart contract audit conducted by the AuditCode specialist multi-agent swarm.")
  lines.push("")
  lines.push("### Audit Metrics & Severity Breakdown")
  lines.push("")
  lines.push("| Severity | Count | Status |")
  lines.push("| :--- | :--- | :--- |")
  lines.push(`| 🔴 **Critical** | ${s.critical} | ${s.critical > 0 ? "Immediate Action Required" : "None Detected"} |`)
  lines.push(`| 🟠 **High** | ${s.high} | ${s.high > 0 ? "Action Required" : "None Detected"} |`)
  lines.push(`| 🟡 **Medium** | ${s.medium} | ${s.medium > 0 ? "Remediation Advised" : "None Detected"} |`)
  lines.push(`| 🔵 **Low** | ${s.low} | Informational / Best Practice |`)
  lines.push(`| ⚪ **Gas Optimization** | ${s.gas} | Gas Improvements |`)
  lines.push(`| ℹ️ **Informational** | ${s.info} | Code Quality / Style |`)
  lines.push("")
  lines.push(`- **Total Contracts in Scope**: ${s.contracts_count}`)
  lines.push(`- **Verified PoC Test Exploits**: ${s.pocs_total}`)
  lines.push(`- **Formal Invariants Evaluated**: ${s.invariants_total}`)
  lines.push("")

  return lines.join("\n")
}

function generateScope(state: EngagementSchema.State): string {
  const lines: string[] = []
  lines.push("## Scope & Architecture Overview")
  lines.push("")

  const contracts = Object.values(state.contracts ?? {})
  if (contracts.length > 0) {
    lines.push("### In-Scope Contracts")
    lines.push("")
    lines.push("| Contract Name | Source Path | SLOC | Proxy Pattern | Compiler |")
    lines.push("| :--- | :--- | :--- | :--- | :--- |")
    for (const c of contracts) {
      lines.push(`| **${c.name}** | \`${c.path}\` | ${c.sloc ?? "?"} | \`${c.proxy_pattern ?? "none"}\` | \`${c.compiler_version ?? "solc"}\` |`)
    }
    lines.push("")
  }

  const actors = Object.values(state.actors ?? {})
  if (actors.length > 0) {
    lines.push("### Roles & Privilege Matrix")
    lines.push("")
    lines.push("| Role | Description | Privileged Functions | Timelock |")
    lines.push("| :--- | :--- | :--- | :--- |")
    for (const a of actors) {
      const funcs = a.privileged_functions?.length ? `\`${a.privileged_functions.join("()`, `")}()\`` : "All Admin"
      lines.push(`| **${a.role_name}** | ${a.description ?? ""} | ${funcs} | ${a.timelock_delay ?? "None"} |`)
    }
    lines.push("")
  }

  const invariants = Object.values(state.invariants ?? {})
  if (invariants.length > 0) {
    lines.push("### Core Protocol Invariants")
    lines.push("")
    lines.push("| Invariant ID | Title & Property | Targets | Status |")
    lines.push("| :--- | :--- | :--- | :--- |")
    for (const inv of invariants) {
      const statusBadge = inv.status === "valid" ? "🟢 VALID" : inv.status === "violated" ? "🔴 VIOLATED" : "⚪ UNTESTED"
      lines.push(`| **${inv.id}** | ${inv.title} | ${(inv.target_contracts ?? []).join(", ") || "Protocol"} | ${statusBadge} |`)
    }
    lines.push("")
  }

  return lines.join("\n")
}

function generateFindings(state: EngagementSchema.State): string {
  const lines: string[] = []
  lines.push("## Detailed Vulnerability Findings")
  lines.push("")

  const topVulns = Object.values(state.vulns ?? {})
  const hostVulns = Object.values(state.hosts).flatMap((h) => h.vulns)
  const allVulns = [...topVulns, ...hostVulns]

  if (allVulns.length === 0) {
    lines.push("No vulnerabilities were recorded in the audit state.")
    return lines.join("\n")
  }

  const sorted = [...allVulns].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity))

  const sevIcons: Record<string, string> = {
    critical: "🔴 [CRITICAL]",
    high: "🟠 [HIGH]",
    medium: "🟡 [MEDIUM]",
    low: "🔵 [LOW]",
    gas: "⚪ [GAS]",
    info: "ℹ️ [INFO]",
  }

  for (let i = 0; i < sorted.length; i++) {
    const v = sorted[i]
    const sev = v.severity ?? "medium"
    const icon = sevIcons[sev] ?? "🟡 [MEDIUM]"
    const id = v.id ?? `AC-${sev.toUpperCase()}-${i + 1}`

    lines.push(`### ${id}: ${v.title}`)
    lines.push("")
    lines.push(`- **Severity**: ${icon}`)
    if (v.bug_class) lines.push(`- **Bug Class**: \`${v.bug_class}\``)
    lines.push(`- **Target Location**: \`${v.contract_name ?? "Contract"}${v.function_name ? `.${v.function_name}()` : ""}\`${v.line_start ? ` (Lines ${v.line_start}${v.line_end ? `-${v.line_end}` : ""})` : ""}`)
    lines.push(`- **Status**: \`${v.status ?? "confirmed"}\`${v.confidence !== undefined ? ` (Confidence: ${(v.confidence * 100).toFixed(0)}%)` : ""}`)
    if (v.discovered_by) lines.push(`- **Discovered By**: \`${v.discovered_by}\``)
    lines.push("")

    if (v.impact) {
      lines.push("#### Impact")
      lines.push(v.impact)
      lines.push("")
    }

    if (v.description || v.root_cause) {
      lines.push("#### Vulnerability Details & Root Cause")
      if (v.root_cause) lines.push(`**Root Cause**: ${v.root_cause}\n`)
      if (v.description) lines.push(v.description)
      lines.push("")
    }

    if (v.attack_path) {
      lines.push("#### Exploit Scenario / Attack Path")
      lines.push(v.attack_path)
      lines.push("")
    }

    if (v.proof_of_concept) {
      lines.push("#### Proof of Concept (PoC)")
      lines.push("```solidity")
      lines.push(v.proof_of_concept)
      lines.push("```")
      lines.push("")
    }

    if (v.minimal_fix) {
      lines.push("#### Remediation (Recommended Fix)")
      lines.push("```diff")
      lines.push(v.minimal_fix)
      lines.push("```")
      lines.push("")
    }

    lines.push("---")
    lines.push("")
  }

  return lines.join("\n")
}

function generateRecommendations(): string {
  return `## General Security Recommendations & Best Practices

1. **Strict CEI Enforcement**: Ensure all state mutations precede external interactions or token transfers.
2. **Safe Token Transfers**: Always use OpenZeppelin's \`SafeERC20\` for transfers to handle non-compliant tokens (e.g. USDT) gracefully.
3. **Robust Oracle Defenses**: Avoid spot-price dependencies; use long-window TWAPs or Chainlink feeds with round freshness checks and L2 sequencer heartbeat verification.
4. **Upgrade Storage Collisions**: For upgradeable contracts, maintain storage gap allocations (\`uint256[50] private __gap\`) and disable implementation initializers.
5. **Continuous Fuzzing**: Implement invariant fuzz testing in Foundry (\`forge test --fuzz-runs 10000\`) covering core solvency and token accounting properties.
`
}

export const ReportGenTool = Tool.define(
  "report_gen",
  Effect.gen(function* () {
    const engagement = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { format?: "markdown" | "json"; sections?: string[]; output_path?: string },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* engagement.get()

          if (!state) {
            return {
              title: "Error",
              metadata: {},
              output: "No audit engagement loaded. Create or load one first.",
            }
          }

          const format = params.format ?? "markdown"
          const output_path = params.output_path

          if (format === "json") {
            const jsonContent = JSON.stringify(state, undefined, 2)
            if (output_path) {
              const dir = nodePath.dirname(output_path)
              nodeFs.mkdirSync(dir, { recursive: true })
              nodeFs.writeFileSync(output_path, jsonContent, "utf-8")
              return {
                title: `Report Exported: ${output_path}`,
                metadata: { format: "json", output_path },
                output: `Audit report exported in JSON format to ${output_path}`,
              }
            }
            return {
              title: "JSON Audit Report",
              metadata: { format: "json" },
              output: jsonContent,
            }
          }

          const reportParts = [
            generateExecutiveSummary(state),
            generateScope(state),
            generateFindings(state),
            generateRecommendations(),
          ]

          const reportMd = reportParts.join("\n\n")

          if (output_path) {
            const dir = nodePath.dirname(output_path)
            nodeFs.mkdirSync(dir, { recursive: true })
            nodeFs.writeFileSync(output_path, reportMd, "utf-8")
            return {
              title: `Report Exported: ${output_path}`,
              metadata: { format: "markdown", output_path },
              output: `Audit report written to ${output_path} (${Object.keys(state.contracts ?? {}).length} contracts, ${EngagementSchema.summary(state).vulnerabilities_total} findings)`,
            }
          }

          return {
            title: "Smart Contract Audit Report",
            metadata: { format: "markdown" },
            output: reportMd,
          }
        }),
    }
  }),
)
