import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import { FSUtil } from "@auditcode/core/fs-util"
import DESCRIPTION from "./nuclei-parse.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  input: Schema.String.annotate({
    description: "Nuclei JSON lines output text or file path to read",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Add discovered vulnerabilities to engagement state (default: true)",
  }),
})

interface NucleiInfo {
  name?: string
  severity?: string
  tags?: string[]
  reference?: string[]
}

interface NucleiResult {
  "template-id": string
  info?: NucleiInfo
  type?: string
  host?: string
  "matched-at"?: string
  ip?: string
  port?: string
  "matcher-name"?: string
  "matcher-status"?: boolean
  timestamp?: string
}

interface ParsedFinding {
  templateId: string
  title: string
  severity: string
  ip: string
  port: number
  matchedAt: string
  matcherName: string
  references: string[]
  tags: string[]
  scanType: string
  vulnId: string
}

function looksLikeFilePath(input: string): boolean {
  const trimmed = input.trimStart()
  if (trimmed.startsWith("/") || trimmed.startsWith("./") || trimmed.startsWith("~/")) return true
  if (/\.(json|jsonl|txt)$/i.test(trimmed.split("\n")[0]!.trim())) return true
  return false
}

function extractCveId(templateId: string, tags: string[]): string | undefined {
  if (!tags.some((t) => t.toLowerCase() === "cve")) return undefined
  const match = /^(cve-\d{4}-\d+)/i.exec(templateId)
  return match ? match[1]!.toUpperCase() : undefined
}

function normalizeSeverity(sev: string | undefined): string {
  const s = (sev ?? "info").toLowerCase()
  if (["critical", "high", "medium", "low", "info"].includes(s)) return s
  return "info"
}

function parseNucleiLines(content: string): ParsedFinding[] {
  const findings: ParsedFinding[] = []
  const seen = new Set<string>()

  for (const line of content.split("\n")) {
    const trimmed = line.trim()
    if (!trimmed || !trimmed.startsWith("{")) continue

    let result: NucleiResult
    try {
      result = JSON.parse(trimmed) as NucleiResult
    } catch {
      continue
    }

    const templateId = result["template-id"]
    if (!templateId) continue

    const ip = result.ip ?? ""
    const port = result.port ? Number(result.port) : 0
    const dedupKey = `${ip}:${templateId}:${port}`
    if (seen.has(dedupKey)) continue
    seen.add(dedupKey)

    const info = result.info ?? {}
    const tags = info.tags ?? []
    const cveId = extractCveId(templateId, tags)

    findings.push({
      templateId,
      title: info.name || templateId,
      severity: normalizeSeverity(info.severity),
      ip,
      port,
      matchedAt: result["matched-at"] ?? result.host ?? "",
      matcherName: result["matcher-name"] ?? "",
      references: info.reference ?? [],
      tags,
      scanType: result.type ?? "unknown",
      vulnId: cveId ?? `nuclei-${templateId}`,
    })
  }

  return findings
}

function formatOutput(findings: ParsedFinding[], autoUpdated: boolean): string {
  const lines: string[] = []
  lines.push(`Parsed ${findings.length} finding${findings.length !== 1 ? "s" : ""} from nuclei output`)
  lines.push("")

  const bySeverity: Record<string, ParsedFinding[]> = {}
  for (const f of findings) {
    const sev = f.severity.toUpperCase()
    if (!bySeverity[sev]) bySeverity[sev] = []
    bySeverity[sev]!.push(f)
  }

  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
  for (const sev of severityOrder) {
    const group = bySeverity[sev]
    if (!group || group.length === 0) continue
    lines.push(`[${sev}] (${group.length})`)
    for (const f of group) {
      const portStr = f.port ? `:${f.port}` : ""
      lines.push(`  ${f.ip}${portStr} — ${f.title} (${f.templateId})`)
      if (f.matchedAt) lines.push(`    matched: ${f.matchedAt}`)
    }
    lines.push("")
  }

  if (autoUpdated) {
    lines.push(`[Auto-updated engagement state: ${findings.length} vulnerabilit${findings.length !== 1 ? "ies" : "y"}]`)
  } else {
    lines.push("[Engagement state not updated (auto_update=false)]")
  }

  return lines.join("\n")
}

export const NucleiParseTool = Tool.define(
  "nuclei_parse",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const fs = yield* FSUtil.Service
    const events = yield* EventV2Bridge.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { input: string; auto_update?: boolean },
        _ctx: Tool.Context,
      ) =>
        Effect.gen(function* () {
          let content = params.input
          const shouldUpdate = params.auto_update !== false

          if (looksLikeFilePath(content.trim())) {
            const filePath = content.trim()
            const exists = yield* fs.existsSafe(filePath)
            if (exists) {
              content = yield* fs.readFileString(filePath)
            }
          }

          const findings = parseNucleiLines(content)

          if (findings.length === 0) {
            return {
              title: "nuclei parse",
              metadata: { findings: 0, auto_updated: false },
              output: "No findings parsed from nuclei output. Verify the input is nuclei JSON lines format (run nuclei with -j flag).",
            }
          }

          const oosHosts: string[] = []

          if (shouldUpdate) {
            const state = yield* store.get()
            const inScopeFindings = findings.filter((f) => {
              if (!f.ip) return true
              if (state && state.scope.targets.length > 0 && state.mode !== "free") {
                const result = ScopeMatcher.checkScope(f.ip, state.scope)
                if (!result.inScope) { oosHosts.push(f.ip); return false }
              }
              return true
            })
            for (const f of inScopeFindings) {
              if (!f.ip) continue

              yield* store.addHost(f.ip, { ip: f.ip })

              const evidence = [
                f.matchedAt ? `matched: ${f.matchedAt}` : "",
                f.matcherName ? `matcher: ${f.matcherName}` : "",
                `template: ${f.templateId}`,
                `type: ${f.scanType}`,
              ]
                .filter(Boolean)
                .join(" | ")

              // I-3: nuclei is a scanner — a template match is UNVERIFIED until a
              // critic/manual check confirms it. Do not fabricate "verified" from
              // severity, and derive confidence from real signal, not severity.
              const evidenceItem = {
                tool: "nuclei",
                command: `nuclei -t ${f.templateId}`,
                output: evidence,
                timestamp: new Date().toISOString(),
                reasoning: `Template ${f.templateId} matched at ${f.matchedAt || "target"}`,
                source_agent: "scanner",
                attempt_number: 1,
                verification_status: "unverified" as const,
              }
              const conf = EngagementSchema.deriveConfidence({ status: "confirmed", evidence_items: [evidenceItem] })
              yield* store.addVuln(f.ip, {
                id: f.vulnId,
                title: f.title,
                severity: f.severity as any,
                status: "confirmed",
                confidence: conf,
                description: `Nuclei ${f.scanType} scan finding. Tags: ${f.tags.join(", ") || "none"}`,
                evidence,
                evidence_items: [{ ...evidenceItem, confidence: conf }],
                service_port: f.port || undefined,
                references: f.references,
              })

              if (state) {
                yield* events.publish(PentestEvent.VulnFound, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  hostIp: f.ip,
                  title: f.title,
                  severity: f.severity,
                  status: "confirmed",
                })
              }
            }

            const updatedState = yield* store.get()
            if (updatedState) yield* store.save(updatedState)
          }

          let output = formatOutput(findings, shouldUpdate)

          if (oosHosts.length > 0) {
            const unique = [...new Set(oosHosts)]
            output += `\n\n[SCOPE] Filtered ${unique.length} out-of-scope finding(s) by host: ${unique.join(", ")}. Not added to engagement state.`
          }

          if (shouldUpdate && findings.length > 0) {
            const highSev = findings.filter((f) => f.severity === "critical" || f.severity === "high")
            if (highSev.length > 0) {
              output += `\n\n[Auto-critic] ${highSev.length} high/critical finding(s) should be validated. Spawn "critic" subagent to check for false positives before reporting.`
            }
          }

          return {
            title: `nuclei: ${findings.length} findings`,
            metadata: {
              findings: findings.length,
              auto_updated: shouldUpdate,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
