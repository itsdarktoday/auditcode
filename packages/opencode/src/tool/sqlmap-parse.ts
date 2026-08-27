import * as nodeFs from "node:fs"
import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import type { EngagementSchema } from "@auditcode/core/engagement/schema"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./sqlmap-parse.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  input: Schema.String.annotate({
    description: "Sqlmap output text (JSON or console) or file path to read",
  }),
  format: Schema.optional(Schema.Literals(["json", "text", "auto"])).annotate({
    description: "Input format. Default: auto-detect from content",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Add discovered SQL injection vulns to engagement state (default: true)",
  }),
})

interface ParsedInjection {
  parameter: string
  place: string
  technique: string
  dbms: string
  title: string
  ip: string
  port: number
  url: string
  databases: string[]
  tables: string[]
}

function looksLikeFilePath(input: string): boolean {
  const trimmed = input.trimStart()
  if (trimmed.startsWith("/") || trimmed.startsWith("./") || trimmed.startsWith("~/")) return true
  if (/\.(json|jsonl|txt|log)$/i.test(trimmed.split("\n")[0]!.trim())) return true
  return false
}

function detectFormat(content: string): "json" | "text" {
  const trimmed = content.trimStart()
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json"
  return "text"
}

function extractHostFromUrl(url: string): { ip: string; port: number } {
  try {
    const parsed = new URL(url)
    const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80
    return { ip: parsed.hostname, port }
  } catch {
    const match = /(?:https?:\/\/)?([^:/]+)(?::(\d+))?/.exec(url)
    if (match) {
      return { ip: match[1]!, port: match[2] ? Number(match[2]) : 80 }
    }
    return { ip: "unknown", port: 80 }
  }
}

function techniqueLabel(code: string): string {
  const map: Record<string, string> = {
    B: "boolean-based blind",
    E: "error-based",
    U: "UNION query",
    S: "stacked queries",
    T: "time-based blind",
    Q: "inline query",
  }
  return map[code] ?? code
}

function parseJson(content: string): ParsedInjection[] {
  const findings: ParsedInjection[] = []
  const seen = new Set<string>()

  let data: any
  try {
    data = JSON.parse(content)
  } catch {
    return findings
  }

  const targets = Array.isArray(data) ? data : data.data ? (Array.isArray(data.data) ? data.data : [data.data]) : [data]

  for (const target of targets) {
    const url = target.url ?? target.target ?? ""
    const { ip, port } = extractHostFromUrl(url)
    const dbms = target.dbms ?? target.back_end_DBMS ?? ""
    const databases: string[] = target.databases ?? []
    const tables: string[] = target.tables ?? []

    const injections = target.injections ?? target.data ?? []
    const injArr = Array.isArray(injections) ? injections : Object.values(injections)

    for (const inj of injArr) {
      const parameter = inj.parameter ?? inj.place ?? "unknown"
      const place = inj.place ?? "GET"
      const techCodes = inj.type ?? inj.technique ?? ""
      const techniques = typeof techCodes === "string"
        ? techCodes.split("").map(techniqueLabel).filter(Boolean)
        : [String(techCodes)]

      for (const technique of techniques) {
        const dedupKey = `${ip}:${parameter}:${technique}`
        if (seen.has(dedupKey)) continue
        seen.add(dedupKey)

        findings.push({
          parameter,
          place,
          technique,
          dbms: dbms || "unknown",
          title: `SQL Injection: ${parameter} (${technique})`,
          ip,
          port,
          url,
          databases,
          tables,
        })
      }
    }

    if (injArr.length === 0 && (dbms || databases.length > 0)) {
      const dedupKey = `${ip}:auto:${dbms}`
      if (!seen.has(dedupKey)) {
        seen.add(dedupKey)
        findings.push({
          parameter: "auto-detected",
          place: "unknown",
          technique: "unspecified",
          dbms: dbms || "unknown",
          title: `SQL Injection: auto-detected (${dbms || "unknown DBMS"})`,
          ip,
          port,
          url,
          databases,
          tables,
        })
      }
    }
  }

  return findings
}

function parseText(content: string): ParsedInjection[] {
  const findings: ParsedInjection[] = []
  const seen = new Set<string>()

  let currentUrl = ""
  let currentDbms = ""
  const databases: string[] = []
  const tables: string[] = []

  const urlPattern = /(?:testing URL|target URL)\s*['"]?(https?:\/\/[^\s'"]+)/i
  const vulnPattern = /(?:Parameter|parameter)\s*['"]?#?(\w+)['"]?\s+(?:is|appears to be)\s+(?:vulnerable|injectable)/i
  const dbmsPattern = /back-end DBMS:\s*(.+)/i
  const techniquePattern = /Type:\s*(.+)/i
  const placePattern = /Place:\s*(\w+)/i
  const dbPattern = /\[\*\]\s+available databases?\s*\[(\d+)\]:/i
  const dbNamePattern = /\[\*\]\s+(\S+)/
  const tablePattern = /Database:\s*(\S+)\s*\n.*Table:\s*(\S+)/gi

  for (const line of content.split("\n")) {
    const trimmed = line.trim()

    const urlMatch = urlPattern.exec(trimmed)
    if (urlMatch) currentUrl = urlMatch[1]!

    const dbmsMatch = dbmsPattern.exec(trimmed)
    if (dbmsMatch) currentDbms = dbmsMatch[1]!.trim()

    const dbMatch = dbPattern.exec(trimmed)
    if (dbMatch) {
      // Next lines will be database names
    }

    const dbNameMatch = /^\[\*\]\s+(\S+)$/.exec(trimmed)
    if (dbNameMatch && !trimmed.includes("available") && !trimmed.includes("fetching")) {
      databases.push(dbNameMatch[1]!)
    }

    const vulnMatch = vulnPattern.exec(trimmed)
    if (vulnMatch) {
      const parameter = vulnMatch[1]!
      const { ip, port } = extractHostFromUrl(currentUrl || "unknown")

      let technique = "unspecified"
      let place = "GET"

      const techIdx = content.indexOf(trimmed)
      const context = content.slice(Math.max(0, techIdx - 500), techIdx + 500)
      const techMatch = techniquePattern.exec(context)
      if (techMatch) technique = techMatch[1]!.trim()
      const placeMatch = placePattern.exec(context)
      if (placeMatch) place = placeMatch[1]!

      const dedupKey = `${ip}:${parameter}:${technique}`
      if (!seen.has(dedupKey)) {
        seen.add(dedupKey)
        findings.push({
          parameter,
          place,
          technique,
          dbms: currentDbms || "unknown",
          title: `SQL Injection: ${parameter} (${technique})`,
          ip,
          port,
          url: currentUrl,
          databases: [...databases],
          tables: [...tables],
        })
      }
    }
  }

  return findings
}

function formatOutput(findings: ParsedInjection[], autoUpdated: boolean): string {
  const lines: string[] = []
  lines.push(`Parsed ${findings.length} SQL injection finding${findings.length !== 1 ? "s" : ""} from sqlmap output`)
  lines.push("")

  for (const f of findings) {
    lines.push(`[${f.dbms ? f.dbms.toUpperCase() : "SQLI"}] ${f.ip}:${f.port} — ${f.title}`)
    lines.push(`  Place: ${f.place} | Parameter: ${f.parameter} | Technique: ${f.technique}`)
    if (f.url) lines.push(`  URL: ${f.url}`)
    if (f.databases.length > 0) lines.push(`  Databases: ${f.databases.join(", ")}`)
    if (f.tables.length > 0) lines.push(`  Tables: ${f.tables.join(", ")}`)
    lines.push("")
  }

  if (autoUpdated) {
    lines.push(`[Auto-updated engagement state: ${findings.length} SQL injection finding${findings.length !== 1 ? "s" : ""}]`)
  } else {
    lines.push("[Engagement state not updated (auto_update=false)]")
  }

  return lines.join("\n")
}

export const SqlmapParseTool = Tool.define(
  "sqlmap_parse",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { input: string; format?: "json" | "text" | "auto"; auto_update?: boolean },
        _ctx: Tool.Context,
      ) =>
        Effect.gen(function* () {
          let content = params.input
          const shouldUpdate = params.auto_update !== false

          if (looksLikeFilePath(content.trim())) {
            const filePath = content.trim().replace(/^~/, process.env.HOME ?? "~")
            try {
              content = nodeFs.readFileSync(filePath, "utf-8")
            } catch {
              return {
                title: "sqlmap parse",
                metadata: { findings: 0, auto_updated: false as boolean },
                output: `Could not read file: ${filePath}`,
              }
            }
          }

          const fmt = params.format === "auto" || !params.format ? detectFormat(content) : params.format
          const findings = fmt === "json" ? parseJson(content) : parseText(content)

          if (findings.length === 0) {
            return {
              title: "sqlmap parse",
              metadata: { findings: 0, auto_updated: false as boolean },
              output: "No SQL injection findings parsed from sqlmap output. Verify the input contains sqlmap results.",
            }
          }

          const oosHosts: string[] = []

          if (shouldUpdate) {
            const state = yield* store.get()
            const inScopeFindings = findings.filter((f) => {
              if (!f.ip || f.ip === "unknown") return true
              if (state && state.scope.targets.length > 0 && state.mode !== "free") {
                const result = ScopeMatcher.checkScope(f.ip, state.scope)
                if (!result.inScope) { oosHosts.push(f.ip); return false }
              }
              return true
            })
            for (const f of inScopeFindings) {
              if (!f.ip || f.ip === "unknown") continue

              yield* store.addHost(f.ip, { ip: f.ip })

              const evidence = [
                `parameter: ${f.parameter}`,
                `place: ${f.place}`,
                `technique: ${f.technique}`,
                `dbms: ${f.dbms}`,
                f.url ? `url: ${f.url}` : "",
                f.databases.length > 0 ? `databases: ${f.databases.join(", ")}` : "",
              ]
                .filter(Boolean)
                .join(" | ")

              yield* store.addVuln(f.ip, {
                id: `sqli-${f.parameter}-${Date.now()}`,
                title: f.title,
                severity: "high",
                status: "confirmed",
                confidence: 0.95,
                description: `SQL Injection via ${f.place} parameter "${f.parameter}" using ${f.technique}. DBMS: ${f.dbms}.`,
                evidence,
                evidence_items: [{
                  tool: "sqlmap",
                  command: `sqlmap -u "${f.url}" -p "${f.parameter}"`,
                  output: evidence,
                  timestamp: new Date().toISOString(),
                  confidence: 0.95,
                }],
                service_port: f.port || undefined,
                references: [],
              })

              if (state) {
                yield* events.publish(PentestEvent.VulnFound, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  hostIp: f.ip,
                  title: f.title,
                  severity: "high",
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
            output += `\n\n[SCOPE] Filtered ${unique.length} out-of-scope host(s): ${unique.join(", ")}. Not added to engagement state.`
          }

          if (shouldUpdate && findings.length > 0) {
            output += `\n\n[Auto-critic] ${findings.length} SQL injection finding(s) detected. Spawn "critic" subagent to verify exploitability and rule out false positives.`
          }

          return {
            title: `sqlmap: ${findings.length} injection${findings.length !== 1 ? "s" : ""}`,
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
