import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import { FSUtil } from "@auditcode/core/fs-util"
import DESCRIPTION from "./gobuster-parse.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  input: Schema.String.annotate({
    description: "Gobuster/feroxbuster output text or file path to read",
  }),
  target_host: Schema.String.annotate({
    description: "Target host IP or domain (required for gobuster relative paths)",
  }),
  target_port: Schema.optional(Schema.Number).annotate({
    description: "Target port (default: 80)",
  }),
  format: Schema.optional(Schema.Literals(["gobuster", "feroxbuster", "auto"])).annotate({
    description: "Input format. Default: auto-detect from content",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Add security-sensitive findings to engagement state (default: true)",
  }),
})

interface ParsedEntry {
  path: string
  status: number
  size: number
  redirect?: string
}

type FindingCategory = "sensitive_file" | "admin_panel" | "backup_file" | "server_info"

interface SecurityFinding {
  path: string
  status: number
  category: FindingCategory
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
}

const SENSITIVE_FILE_PATTERNS: Array<{ pattern: RegExp; title: string; severity: "high" | "medium" }> = [
  { pattern: /\/\.git(\/|$)/i, title: "Git Repository Exposed", severity: "high" },
  { pattern: /\/\.svn(\/|$)/i, title: "SVN Repository Exposed", severity: "high" },
  { pattern: /\/\.env$/i, title: "Environment File Exposed (.env)", severity: "high" },
  { pattern: /\/\.DS_Store$/i, title: "DS_Store File Exposed", severity: "medium" },
  { pattern: /\/web\.config$/i, title: "web.config Exposed", severity: "high" },
  { pattern: /\/\.htaccess$/i, title: ".htaccess Exposed", severity: "medium" },
  { pattern: /\/\.htpasswd$/i, title: ".htpasswd Exposed", severity: "high" },
  { pattern: /\/wp-config\.php/i, title: "WordPress Config Exposed", severity: "high" },
]

const ADMIN_PANEL_PATTERNS: Array<{ pattern: RegExp; title: string }> = [
  { pattern: /\/phpmyadmin/i, title: "phpMyAdmin Panel Exposed" },
  { pattern: /\/wp-admin/i, title: "WordPress Admin Panel Exposed" },
  { pattern: /\/admin(\/|$)/i, title: "Admin Panel Exposed" },
  { pattern: /\/manager(\/|$)/i, title: "Manager Panel Exposed" },
  { pattern: /\/administrator/i, title: "Administrator Panel Exposed" },
  { pattern: /\/console(\/|$)/i, title: "Console Exposed" },
  { pattern: /\/dashboard(\/|$)/i, title: "Dashboard Exposed" },
]

const BACKUP_FILE_PATTERNS: Array<{ pattern: RegExp; title: string; severity: "high" | "medium" }> = [
  { pattern: /\.bak$/i, title: "Backup File Exposed", severity: "medium" },
  { pattern: /\.sql$/i, title: "SQL Dump Exposed", severity: "high" },
  { pattern: /\.zip$/i, title: "Archive File Exposed", severity: "medium" },
  { pattern: /\.tar(\.gz)?$/i, title: "Archive File Exposed", severity: "medium" },
  { pattern: /\.7z$/i, title: "Archive File Exposed", severity: "medium" },
  { pattern: /backup/i, title: "Backup Directory/File Exposed", severity: "medium" },
  { pattern: /\.old$/i, title: "Old File Exposed", severity: "medium" },
  { pattern: /\.orig$/i, title: "Original File Exposed", severity: "medium" },
]

const SERVER_INFO_PATTERNS: Array<{ pattern: RegExp; title: string }> = [
  { pattern: /\/server-status/i, title: "Apache Server Status Exposed" },
  { pattern: /\/server-info/i, title: "Apache Server Info Exposed" },
  { pattern: /\/status$/i, title: "Status Page Exposed" },
  { pattern: /\/info\.php/i, title: "PHP Info Page Exposed" },
  { pattern: /\/phpinfo/i, title: "PHP Info Page Exposed" },
]

function looksLikeFilePath(input: string): boolean {
  const trimmed = input.trimStart()
  if (trimmed.startsWith("/") && !trimmed.includes("(Status:") && !trimmed.includes("\n")) return true
  if (trimmed.startsWith("./") || trimmed.startsWith("~/")) return true
  if (/\.(txt|log|out|json)$/i.test(trimmed.split("\n")[0]!.trim())) return true
  return false
}

function detectFormat(content: string): "gobuster" | "feroxbuster" {
  if (/\(Status:\s*\d+\)/.test(content)) return "gobuster"
  if (/^\d{3}\s+(GET|POST|PUT|HEAD|OPTIONS)\s/m.test(content)) return "feroxbuster"
  return "gobuster"
}

function parseGobuster(content: string): ParsedEntry[] {
  const entries: ParsedEntry[] = []
  const pattern = /^(\/\S+)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?(?:\s*\[--> (.*?)\])?/

  for (const line of content.split("\n")) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("=") || trimmed.startsWith("Gobuster") || trimmed.startsWith("[")) continue
    const match = pattern.exec(trimmed)
    if (!match) continue

    entries.push({
      path: match[1]!,
      status: Number(match[2]),
      size: Number(match[3] ?? 0),
      redirect: match[4] || undefined,
    })
  }

  return entries
}

function parseFeroxbuster(content: string): ParsedEntry[] {
  const entries: ParsedEntry[] = []
  const pattern = /^(\d{3})\s+\w+\s+\d+l\s+\d+w\s+(\d+)c\s+(https?:\/\/\S+?)(?:\s+=>\s+(\S+))?$/

  for (const line of content.split("\n")) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) continue
    const match = pattern.exec(trimmed)
    if (!match) continue

    let urlPath: string
    try {
      urlPath = new URL(match[3]!).pathname
    } catch {
      urlPath = match[3]!
    }

    entries.push({
      path: urlPath,
      status: Number(match[1]),
      size: Number(match[2]),
      redirect: match[4] || undefined,
    })
  }

  return entries
}

function classifyFindings(entries: ParsedEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = []
  const seen = new Set<string>()

  for (const entry of entries) {
    if (entry.status >= 400 && entry.status !== 403) continue

    for (const p of SENSITIVE_FILE_PATTERNS) {
      if (p.pattern.test(entry.path) && (entry.status < 400 || entry.status === 403)) {
        const key = `sensitive:${p.title}:${entry.path}`
        if (seen.has(key)) continue
        seen.add(key)
        findings.push({
          path: entry.path,
          status: entry.status,
          category: "sensitive_file",
          title: p.title,
          severity: entry.status < 400 ? p.severity : "low",
        })
      }
    }

    for (const p of ADMIN_PANEL_PATTERNS) {
      if (p.pattern.test(entry.path) && entry.status < 400) {
        const key = `admin:${p.title}:${entry.path}`
        if (seen.has(key)) continue
        seen.add(key)
        findings.push({
          path: entry.path,
          status: entry.status,
          category: "admin_panel",
          title: p.title,
          severity: "medium",
        })
      }
    }

    for (const p of BACKUP_FILE_PATTERNS) {
      if (p.pattern.test(entry.path) && entry.status < 400) {
        const key = `backup:${p.title}:${entry.path}`
        if (seen.has(key)) continue
        seen.add(key)
        findings.push({
          path: entry.path,
          status: entry.status,
          category: "backup_file",
          title: p.title,
          severity: p.severity,
        })
      }
    }

    for (const p of SERVER_INFO_PATTERNS) {
      if (p.pattern.test(entry.path) && entry.status < 400) {
        const key = `info:${p.title}:${entry.path}`
        if (seen.has(key)) continue
        seen.add(key)
        findings.push({
          path: entry.path,
          status: entry.status,
          category: "server_info",
          title: p.title,
          severity: "low",
        })
      }
    }
  }

  return findings
}

function formatOutput(
  entries: ParsedEntry[],
  findings: SecurityFinding[],
  autoUpdated: boolean,
  targetHost: string,
  targetPort: number,
): string {
  const lines: string[] = []
  lines.push(`Parsed ${entries.length} path${entries.length !== 1 ? "s" : ""} from directory brute-force output`)
  lines.push("")

  if (findings.length > 0) {
    lines.push("SECURITY FINDINGS:")
    for (const f of findings) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.title}: ${f.path} (${f.status})`)
    }
    lines.push("")
  }

  const ok = entries.filter((e) => e.status >= 200 && e.status < 300)
  const redirects = entries.filter((e) => e.status >= 300 && e.status < 400)
  const forbidden = entries.filter((e) => e.status === 403)

  if (ok.length > 0) {
    lines.push(`Accessible paths (${ok.length}):`)
    for (const e of ok.slice(0, 30)) {
      lines.push(`  ${e.status}  ${e.path.padEnd(40)} ${e.size > 0 ? `[${e.size}B]` : ""}`.trimEnd())
    }
    if (ok.length > 30) lines.push(`  ... and ${ok.length - 30} more`)
    lines.push("")
  }

  if (redirects.length > 0) {
    lines.push(`Redirects (${redirects.length}):`)
    for (const e of redirects.slice(0, 15)) {
      lines.push(`  ${e.status}  ${e.path} --> ${e.redirect ?? "?"}`)
    }
    if (redirects.length > 15) lines.push(`  ... and ${redirects.length - 15} more`)
    lines.push("")
  }

  if (forbidden.length > 0) {
    lines.push(`Forbidden (${forbidden.length}): ${forbidden.slice(0, 10).map((e) => e.path).join(", ")}${forbidden.length > 10 ? ` ... +${forbidden.length - 10}` : ""}`)
    lines.push("")
  }

  if (autoUpdated) {
    lines.push(`[Auto-updated engagement state: ${findings.length} finding${findings.length !== 1 ? "s" : ""} on ${targetHost}:${targetPort}]`)
  } else {
    lines.push("[Engagement state not updated (auto_update=false)]")
  }

  lines.push("")
  lines.push(`Relevant service skill available: "svc-web-server". Load via the skill tool for web-specific attack techniques.`)

  return lines.join("\n")
}

export const GobusterParseTool = Tool.define(
  "gobuster_parse",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const fsUtil = yield* FSUtil.Service
    const events = yield* EventV2Bridge.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          input: string
          target_host: string
          target_port?: number
          format?: "gobuster" | "feroxbuster" | "auto"
          auto_update?: boolean
        },
        _ctx: Tool.Context,
      ) =>
        Effect.gen(function* () {
          let content = params.input
          const shouldUpdate = params.auto_update !== false
          const targetPort = params.target_port ?? 80

          if (looksLikeFilePath(content.trim())) {
            const filePath = content.trim()
            const exists = yield* fsUtil.existsSafe(filePath)
            if (exists) {
              content = yield* fsUtil.readFileString(filePath)
            }
          }

          const format =
            params.format === "auto" || !params.format ? detectFormat(content) : params.format

          const entries = format === "feroxbuster" ? parseFeroxbuster(content) : parseGobuster(content)

          if (entries.length === 0) {
            return {
              title: "gobuster parse",
              metadata: { paths: 0, findings: 0, format, auto_updated: false },
              output:
                "No paths found in the provided output. Verify the input is gobuster (-o) or feroxbuster output.",
            }
          }

          const findings = classifyFindings(entries)
          let oosFiltered = false

          if (shouldUpdate && findings.length > 0) {
            const state = yield* store.get()

            if (state && state.scope.targets.length > 0 && state.mode !== "free") {
              const scopeResult = ScopeMatcher.checkScope(params.target_host, state.scope)
              if (!scopeResult.inScope) {
                oosFiltered = true
                const output = formatOutput(entries, findings, false, params.target_host, targetPort)
                return {
                  title: `gobuster: ${entries.length} paths, ${findings.length} findings`,
                  metadata: {
                    paths: entries.length,
                    findings: findings.length,
                    format,
                    auto_updated: false,
                  },
                  output: output + `\n\n[SCOPE] Target host ${params.target_host} is out of scope. Findings not added to engagement state.`,
                }
              }
            }

            for (const finding of findings) {
              const evidenceStr = `gobuster/feroxbuster: ${finding.path} (${finding.status})`
              yield* store.addVuln(params.target_host, {
                id: `web-${finding.category}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                title: finding.title,
                severity: finding.severity,
                status: "suspected",
                confidence: 0.4,
                description: `${finding.path} returned HTTP ${finding.status}`,
                evidence: evidenceStr,
                evidence_items: [{
                  tool: "gobuster",
                  output: evidenceStr,
                  timestamp: new Date().toISOString(),
                  confidence: 0.4,
                }],
                service_port: targetPort,
              })

              if (state) {
                yield* events.publish(PentestEvent.VulnFound, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  hostIp: params.target_host,
                  title: finding.title,
                  severity: finding.severity,
                  status: "suspected",
                })
              }
            }

            const ok = entries.filter((e) => e.status >= 200 && e.status < 300)
            if (ok.length > 0) {
              const noteText = `Directory brute-force: ${ok.length} accessible paths found (port ${targetPort}). Key: ${ok.slice(0, 10).map((e) => e.path).join(", ")}`
              const currentState = yield* store.get()
              if (currentState) {
                const host = currentState.hosts[params.target_host]
                if (host) {
                  yield* store.addHost(params.target_host, {
                    notes: [...host.notes, noteText],
                  })
                }
              }
            }

            const updatedState = yield* store.get()
            if (updatedState) yield* store.save(updatedState)
          }

          const output = formatOutput(entries, findings, shouldUpdate, params.target_host, targetPort)

          return {
            title: `gobuster: ${entries.length} paths, ${findings.length} findings`,
            metadata: {
              paths: entries.length,
              findings: findings.length,
              format,
              auto_updated: shouldUpdate,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
