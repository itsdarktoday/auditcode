import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import { FSUtil } from "@auditcode/core/fs-util"
import DESCRIPTION from "./cme-parse.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  input: Schema.String.annotate({
    description: "CrackMapExec/NetExec output text or file path to read",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Add discovered creds/access/hosts to engagement state (default: true)",
  }),
})

interface ParsedLine {
  protocol: string
  ip: string
  port: number
  hostname: string
  status: "success" | "failure" | "info"
  message: string
  isPwned: boolean
}

interface ParsedCredential {
  domain: string
  username: string
  secret: string
  protocol: string
  ip: string
  port: number
  hostname: string
  isAdmin: boolean
}

interface ParsedHostInfo {
  ip: string
  hostname: string
  os: string
  domain: string
  signing: boolean | undefined
  smbv1: boolean | undefined
}

function looksLikeFilePath(input: string): boolean {
  const trimmed = input.trimStart()
  if (trimmed.startsWith("/") || trimmed.startsWith("./") || trimmed.startsWith("~/")) return true
  if (/\.(txt|log|out)$/i.test(trimmed.split("\n")[0]!.trim())) return true
  return false
}

const LINE_REGEX = /^(\S+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)\s+(\S+)\s+\[([*+\-!])\]\s+(.*)$/

function parseLine(line: string): ParsedLine | undefined {
  const match = LINE_REGEX.exec(line.trim())
  if (!match) return undefined

  const statusChar = match[5]!
  let status: ParsedLine["status"]
  if (statusChar === "+") status = "success"
  else if (statusChar === "-") status = "failure"
  else status = "info"

  return {
    protocol: match[1]!.toUpperCase(),
    ip: match[2]!,
    port: Number(match[3]!),
    hostname: match[4]!,
    status,
    message: match[6]!,
    isPwned: match[6]!.includes("(Pwn3d!)"),
  }
}

const CRED_REGEX = /^(?:([^\\:]+)\\)?([^:]+):(.+?)(?:\s+\(Pwn3d!\))?$/

function parseCredential(parsed: ParsedLine): ParsedCredential | undefined {
  if (parsed.status !== "success") return undefined
  const match = CRED_REGEX.exec(parsed.message.trim())
  if (!match) return undefined

  return {
    domain: match[1] ?? "",
    username: match[2]!,
    secret: match[3]!.replace(/\s*\(Pwn3d!\)\s*$/, ""),
    protocol: parsed.protocol,
    ip: parsed.ip,
    port: parsed.port,
    hostname: parsed.hostname,
    isAdmin: parsed.isPwned,
  }
}

const OS_INFO_REGEX = /^(Windows\s+\S+.*?)\s+\(name:(\S+)\)\s+\(domain:(\S+)\)(?:\s+\(signing:(True|False)\))?(?:\s+\(SMBv1:(True|False)\))?/

function parseHostInfo(parsed: ParsedLine): ParsedHostInfo | undefined {
  if (parsed.status !== "info") return undefined
  const match = OS_INFO_REGEX.exec(parsed.message)
  if (!match) return undefined

  return {
    ip: parsed.ip,
    hostname: match[2]!,
    os: match[1]!,
    domain: match[3]!,
    signing: match[4] !== undefined ? match[4] === "True" : undefined,
    smbv1: match[5] !== undefined ? match[5] === "True" : undefined,
  }
}

function credKey(c: ParsedCredential): string {
  return `${c.ip}:${c.protocol}:${c.domain}\\${c.username}`
}

function credId(c: ParsedCredential): string {
  const prefix = c.domain ? `${c.domain}\\` : ""
  return `${prefix}${c.username}`.toLowerCase().replace(/[^a-z0-9_\\-]/g, "_")
}

function formatOutput(
  totalLines: number,
  credentials: ParsedCredential[],
  hosts: ParsedHostInfo[],
  failures: number,
  autoUpdated: boolean,
): string {
  const lines: string[] = []
  const adminCreds = credentials.filter((c) => c.isAdmin)
  const userCreds = credentials.filter((c) => !c.isAdmin)

  lines.push(`Parsed ${totalLines} lines: ${credentials.length} valid creds (${adminCreds.length} admin), ${hosts.length} hosts identified, ${failures} failed auths`)
  lines.push("")

  if (adminCreds.length > 0) {
    lines.push("Admin access (Pwn3d!):")
    for (const c of adminCreds) {
      const domain = c.domain ? `${c.domain}\\` : ""
      lines.push(`  ${c.protocol.padEnd(6)} ${c.ip}:${c.port} ${c.hostname} ${domain}${c.username}:${c.secret}`)
    }
    lines.push("")
  }

  if (userCreds.length > 0) {
    lines.push("Valid credentials:")
    for (const c of userCreds) {
      const domain = c.domain ? `${c.domain}\\` : ""
      lines.push(`  ${c.protocol.padEnd(6)} ${c.ip}:${c.port} ${c.hostname} ${domain}${c.username}:${c.secret}`)
    }
    lines.push("")
  }

  if (hosts.length > 0) {
    lines.push("Host info:")
    for (const h of hosts) {
      const parts = [`  ${h.ip} (${h.hostname})`, h.os]
      if (h.domain) parts.push(`domain:${h.domain}`)
      if (h.signing !== undefined) parts.push(`signing:${h.signing}`)
      if (h.smbv1 !== undefined) parts.push(`SMBv1:${h.smbv1}`)
      lines.push(parts.join(" "))
    }
    lines.push("")
  }

  if (credentials.length === 0 && hosts.length === 0) {
    lines.push("No credentials or host info found in output.")
    lines.push("")
  }

  if (autoUpdated) {
    lines.push(`[Auto-updated engagement state: ${credentials.length} creds, ${adminCreds.length} access entries, ${hosts.length} hosts]`)
  } else {
    lines.push("[Engagement state not updated (auto_update=false)]")
  }

  return lines.join("\n")
}

export const CmeParseTool = Tool.define(
  "cme_parse",
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

          const contentLines = content.split("\n")
          const credentials: ParsedCredential[] = []
          const hosts: ParsedHostInfo[] = []
          const seenCreds = new Set<string>()
          const seenHosts = new Set<string>()
          let failures = 0

          for (const line of contentLines) {
            const parsed = parseLine(line)
            if (!parsed) continue

            if (parsed.status === "failure") {
              failures++
              continue
            }

            if (parsed.status === "success") {
              const cred = parseCredential(parsed)
              if (cred) {
                const key = credKey(cred)
                if (!seenCreds.has(key)) {
                  seenCreds.add(key)
                  credentials.push(cred)
                }
              }
              continue
            }

            if (parsed.status === "info") {
              const hostInfo = parseHostInfo(parsed)
              if (hostInfo && !seenHosts.has(hostInfo.ip)) {
                seenHosts.add(hostInfo.ip)
                hosts.push(hostInfo)
              }
            }
          }

          const oosIPs: string[] = []

          if (shouldUpdate) {
            const state = yield* store.get()
            const inScopeHosts = hosts.filter((h) => {
              if (state && state.scope.targets.length > 0 && state.mode !== "free") {
                const result = ScopeMatcher.checkScope(h.ip, state.scope)
                if (!result.inScope) { oosIPs.push(h.ip); return false }
              }
              return true
            })
            const inScopeCreds = credentials.filter((c) => {
              if (state && state.scope.targets.length > 0 && state.mode !== "free") {
                const result = ScopeMatcher.checkScope(c.ip, state.scope)
                if (!result.inScope) { if (!oosIPs.includes(c.ip)) oosIPs.push(c.ip); return false }
              }
              return true
            })

            for (const h of inScopeHosts) {
              yield* store.addHost(h.ip, {
                ip: h.ip,
                hostname: h.hostname,
                os: h.os,
              })

              if (state) {
                yield* events.publish(PentestEvent.HostDiscovered, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  ip: h.ip,
                  hostname: h.hostname,
                  serviceCount: 0,
                })
              }

              if (h.signing === false && state) {
                const smbEvidence = `NetExec output: signing:False on ${h.ip}`
                yield* store.addVuln(h.ip, {
                  id: `smb-signing-disabled-${h.ip}`,
                  title: "SMB Signing Disabled",
                  severity: "medium",
                  status: "confirmed",
                  confidence: 0.95,
                  description: "SMB signing is not enforced, enabling NTLM relay attacks.",
                  evidence: smbEvidence,
                  evidence_items: [{
                    tool: "netexec",
                    command: `netexec smb ${h.ip}`,
                    output: smbEvidence,
                    timestamp: new Date().toISOString(),
                    confidence: 0.95,
                    reasoning: "SMB signing disabled detected in NetExec banner, enables NTLM relay",
                    source_agent: "scanner",
                    attempt_number: 1,
                    verification_status: "verified",
                  }],
                  service_port: 445,
                  references: [],
                })
                yield* events.publish(PentestEvent.VulnFound, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  hostIp: h.ip,
                  title: "SMB Signing Disabled",
                  severity: "medium",
                  status: "confirmed",
                })
              }
            }

            for (const c of inScopeCreds) {
              const id = credId(c)
              const domain = c.domain ? `${c.domain}\\` : ""
              const credType = c.secret.match(/^[a-f0-9]{32}:[a-f0-9]{32}$/i) ? "ntlm_hash" : "password"

              yield* store.addCredential(id, {
                cred_type: credType,
                username: `${domain}${c.username}`,
                value: c.secret,
                source: `cme ${c.protocol} ${c.ip}:${c.port}`,
                valid_for: [`${c.ip}:${c.port}/${c.protocol}`],
                confidence: 0.95,
                domain: c.domain || undefined,
              })

              if (state) {
                yield* events.publish(PentestEvent.CredentialFound, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  credId: id,
                  username: `${domain}${c.username}`,
                  credType,
                })
              }

              if (state?.hosts[c.ip]) {
                const level = c.isAdmin ? ("system" as const) : ("user" as const)
                yield* store.addAccess(c.ip, {
                  access_type: c.protocol.toLowerCase(),
                  username: `${domain}${c.username}`,
                  level,
                  confidence: 0.95,
                  credential_id: id,
                  details: c.isAdmin ? "Pwn3d! — admin access confirmed" : "Valid credentials",
                })

                yield* events.publish(PentestEvent.AccessGained, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  hostIp: c.ip,
                  username: `${domain}${c.username}`,
                  level,
                  accessType: c.protocol.toLowerCase(),
                })

                // Auto-create relationships
                yield* store.addRelationship({
                  source_type: "credential",
                  source_id: id,
                  rel_type: "AUTHENTICATES_TO",
                  target_type: "host",
                  target_id: c.ip,
                  metadata: `${c.protocol} port:${c.port}`,
                })
                if (c.isAdmin) {
                  yield* store.addRelationship({
                    source_type: "credential",
                    source_id: id,
                    rel_type: "ADMIN_OF",
                    target_type: "host",
                    target_id: c.ip,
                  })
                }
              }
            }

            const updatedState = yield* store.get()
            if (updatedState) yield* store.save(updatedState)
          }

          let output = formatOutput(contentLines.length, credentials, hosts, failures, shouldUpdate)

          if (oosIPs.length > 0) {
            const unique = [...new Set(oosIPs)]
            output += `\n\n[SCOPE] Filtered ${unique.length} out-of-scope host(s): ${unique.join(", ")}. Not added to engagement state.`
          }

          if (shouldUpdate) {
            const adminCreds = credentials.filter((c) => c.isAdmin)
            if (adminCreds.length > 0) {
              output += `\n\n[Auto-critic] ${adminCreds.length} admin access(es) found — consider spawning "critic" subagent to validate Pwn3d claims and evidence quality.`
            }
          }

          return {
            title: `cme: ${credentials.length} creds, ${credentials.filter((c) => c.isAdmin).length} admin`,
            metadata: {
              credentials: credentials.length,
              admin_access: credentials.filter((c) => c.isAdmin).length,
              hosts: hosts.length,
              failures,
              auto_updated: shouldUpdate,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
