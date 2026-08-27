import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import { FSUtil } from "@auditcode/core/fs-util"
import DESCRIPTION from "./bloodhound-parse.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  input: Schema.String.annotate({
    description: "BloodHound/SharpHound JSON data or file path to read",
  }),
  data_type: Schema.optional(
    Schema.Literals(["computers", "users", "groups", "domains", "gpos", "auto"]),
  ).annotate({
    description:
      "Type of BloodHound collection data. Default: auto-detect from JSON structure",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Add discovered data to engagement state (default: true)",
  }),
})

// ---------- Interfaces for parsed BloodHound JSON ----------

interface BHComputer {
  name: string
  operatingsystem: string | null
  enabled: boolean
  haslaps: boolean
  unconstraineddelegation: boolean
  objectid: string
  domain: string | null
}

interface BHUser {
  name: string
  enabled: boolean
  admincount: boolean
  dontreqpreauth: boolean
  hasspn: boolean
  serviceprincipalnames: string[] | null
  objectid: string
  domain: string | null
}

interface BHGroupMember {
  ObjectIdentifier: string
  ObjectType: string
}

interface BHGroup {
  name: string
  admincount: boolean
  members: BHGroupMember[]
  objectid: string
}

interface BHTrust {
  TargetDomainName: string
  TrustDirection: number | string
  TrustType: number | string
  IsTransitive: boolean
}

interface BHDomain {
  name: string
  domain: string | null
  functionallevel: string | null
  trusts: BHTrust[]
  objectid: string
}

interface BHGPO {
  name: string
  gpcpath: string | null
  objectid: string
}

// ---------- Auto-detection ----------

type DataType = "computers" | "users" | "groups" | "domains" | "gpos"

function detectDataType(firstItem: Record<string, unknown>): DataType | undefined {
  const props = firstItem.Properties ?? firstItem
  if (typeof props !== "object" || props === null) return undefined

  const p = props as Record<string, unknown>

  // Order matters: check most specific keys first
  if ("operatingsystem" in p) return "computers"
  if ("hasspn" in p || "dontreqpreauth" in p || "serviceprincipalnames" in p) return "users"
  if ("gpcpath" in p) return "gpos"

  // Groups and domains both have name, but domains have Trusts
  if ("Trusts" in firstItem || "trusts" in firstItem || "functionallevel" in p) return "domains"
  if ("Members" in firstItem || "members" in firstItem) return "groups"

  return undefined
}

// ---------- Extraction helpers ----------

function extractProps(item: Record<string, unknown>): Record<string, unknown> {
  return (item.Properties ?? item) as Record<string, unknown>
}

function str(val: unknown): string {
  return typeof val === "string" ? val : ""
}

function bool(val: unknown): boolean {
  return val === true
}

function strArray(val: unknown): string[] {
  if (Array.isArray(val)) return val.filter((v) => typeof v === "string")
  return []
}

// ---------- Parsers for each type ----------

function parseComputers(data: Record<string, unknown>[]): BHComputer[] {
  return data.map((item) => {
    const p = extractProps(item)
    return {
      name: str(p.name),
      operatingsystem: typeof p.operatingsystem === "string" ? p.operatingsystem : null,
      enabled: bool(p.enabled),
      haslaps: bool(p.haslaps),
      unconstraineddelegation: bool(p.unconstraineddelegation),
      objectid: str((item as Record<string, unknown>).ObjectIdentifier ?? p.objectid),
      domain: typeof p.domain === "string" ? p.domain : null,
    }
  })
}

function parseUsers(data: Record<string, unknown>[]): BHUser[] {
  return data.map((item) => {
    const p = extractProps(item)
    return {
      name: str(p.name),
      enabled: bool(p.enabled),
      admincount: bool(p.admincount),
      dontreqpreauth: bool(p.dontreqpreauth),
      hasspn: bool(p.hasspn),
      serviceprincipalnames: Array.isArray(p.serviceprincipalnames)
        ? strArray(p.serviceprincipalnames)
        : null,
      objectid: str((item as Record<string, unknown>).ObjectIdentifier ?? p.objectid),
      domain: typeof p.domain === "string" ? p.domain : null,
    }
  })
}

function parseGroups(data: Record<string, unknown>[]): BHGroup[] {
  return data.map((item) => {
    const p = extractProps(item)
    const rawMembers =
      (item as Record<string, unknown>).Members ??
      (item as Record<string, unknown>).members ??
      []
    const members: BHGroupMember[] = Array.isArray(rawMembers)
      ? rawMembers
          .filter((m): m is Record<string, unknown> => typeof m === "object" && m !== null)
          .map((m) => ({
            ObjectIdentifier: str(m.ObjectIdentifier),
            ObjectType: str(m.ObjectType),
          }))
      : []
    return {
      name: str(p.name),
      admincount: bool(p.admincount),
      members,
      objectid: str((item as Record<string, unknown>).ObjectIdentifier ?? p.objectid),
    }
  })
}

function parseDomains(data: Record<string, unknown>[]): BHDomain[] {
  return data.map((item) => {
    const p = extractProps(item)
    const rawTrusts =
      (item as Record<string, unknown>).Trusts ??
      (item as Record<string, unknown>).trusts ??
      []
    const trusts: BHTrust[] = Array.isArray(rawTrusts)
      ? rawTrusts
          .filter((t): t is Record<string, unknown> => typeof t === "object" && t !== null)
          .map((t) => ({
            TargetDomainName: str(t.TargetDomainName),
            TrustDirection: (t.TrustDirection ?? 0) as number | string,
            TrustType: (t.TrustType ?? 0) as number | string,
            IsTransitive: bool(t.IsTransitive),
          }))
      : []
    return {
      name: str(p.name),
      domain: typeof p.domain === "string" ? p.domain : null,
      functionallevel: typeof p.functionallevel === "string" ? p.functionallevel : null,
      trusts,
      objectid: str((item as Record<string, unknown>).ObjectIdentifier ?? p.objectid),
    }
  })
}

function parseGPOs(data: Record<string, unknown>[]): BHGPO[] {
  return data.map((item) => {
    const p = extractProps(item)
    return {
      name: str(p.name),
      gpcpath: typeof p.gpcpath === "string" ? p.gpcpath : null,
      objectid: str((item as Record<string, unknown>).ObjectIdentifier ?? p.objectid),
    }
  })
}

// ---------- Trust direction helpers ----------

function trustDirectionLabel(dir: number | string): string {
  if (dir === 0 || dir === "Disabled") return "disabled"
  if (dir === 1 || dir === "Inbound") return "inbound"
  if (dir === 2 || dir === "Outbound") return "outbound"
  if (dir === 3 || dir === "Bidirectional") return "bidirectional"
  return String(dir)
}

function trustTypeLabel(t: number | string): string {
  if (t === 0 || t === "ParentChild") return "parent-child"
  if (t === 1 || t === "CrossLink") return "cross-link"
  if (t === 2 || t === "Forest") return "forest"
  if (t === 3 || t === "External") return "external"
  return String(t)
}

// ---------- File path detection ----------

function looksLikeFilePath(input: string): boolean {
  const trimmed = input.trimStart()
  if (trimmed.startsWith("/") || trimmed.startsWith("./") || trimmed.startsWith("~/"))
    return true
  if (/\.(json)$/i.test(trimmed.split("\n")[0]!.trim())) return true
  return false
}

// ---------- Output formatting ----------

interface ParseSummary {
  type: DataType
  totalItems: number
  findings: string[]
  stateUpdates: string[]
}

function formatOutput(summaries: ParseSummary[], autoUpdated: boolean): string {
  const lines: string[] = []

  for (const s of summaries) {
    lines.push(`[${s.type}] Parsed ${s.totalItems} item${s.totalItems !== 1 ? "s" : ""}`)

    if (s.findings.length > 0) {
      lines.push("")
      lines.push("Security findings:")
      for (const f of s.findings) {
        lines.push(`  ${f}`)
      }
    }

    if (s.stateUpdates.length > 0) {
      lines.push("")
      lines.push("State updates:")
      for (const u of s.stateUpdates) {
        lines.push(`  ${u}`)
      }
    }

    lines.push("")
  }

  if (autoUpdated) {
    lines.push("[Auto-updated engagement state]")
  } else {
    lines.push("[Engagement state not updated (auto_update=false)]")
  }

  return lines.join("\n")
}

// ---------- Hostname-to-IP helper ----------

function hostnameToIp(name: string): string {
  // BloodHound names are typically FQDN like "DC01.CORP.LOCAL"
  // We use the hostname as-is since we don't have IP resolution
  return name.split(".")[0]?.toUpperCase() || name.toUpperCase()
}

// ---------- Tool definition ----------

export const BloodHoundParseTool = Tool.define(
  "bloodhound_parse",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const fs = yield* FSUtil.Service
    const events = yield* EventV2Bridge.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          input: string
          data_type?: "computers" | "users" | "groups" | "domains" | "gpos" | "auto"
          auto_update?: boolean
        },
        _ctx: Tool.Context,
      ) =>
        Effect.gen(function* () {
          let content = params.input
          const shouldUpdate = params.auto_update !== false
          const requestedType = params.data_type === "auto" ? undefined : params.data_type

          // Resolve file path if input looks like a path
          if (looksLikeFilePath(content.trim())) {
            const filePath = content.trim()
            const exists = yield* fs.existsSafe(filePath)
            if (exists) {
              content = yield* fs.readFileString(filePath)
            }
          }

          const emptyResult = (output: string) => ({
            title: "bloodhound parse",
            metadata: {
              data_type: "unknown" as string,
              total_items: 0,
              findings: 0,
              hosts_added: 0,
              vulns_added: 0,
              auto_updated: false,
            },
            output,
          })

          // Parse JSON
          let parsed: unknown
          try {
            parsed = JSON.parse(content)
          } catch {
            return emptyResult(
              "Failed to parse JSON. Ensure the input is valid BloodHound/SharpHound JSON collection data.",
            )
          }

          // Extract data array — SharpHound wraps in { data: [...] } or { computers: [...] } etc.
          let dataArray: Record<string, unknown>[]
          if (Array.isArray(parsed)) {
            dataArray = parsed as Record<string, unknown>[]
          } else if (typeof parsed === "object" && parsed !== null) {
            const obj = parsed as Record<string, unknown>
            if (Array.isArray(obj.data)) {
              dataArray = obj.data as Record<string, unknown>[]
            } else if (Array.isArray(obj.computers)) {
              dataArray = obj.computers as Record<string, unknown>[]
            } else if (Array.isArray(obj.users)) {
              dataArray = obj.users as Record<string, unknown>[]
            } else if (Array.isArray(obj.groups)) {
              dataArray = obj.groups as Record<string, unknown>[]
            } else if (Array.isArray(obj.domains)) {
              dataArray = obj.domains as Record<string, unknown>[]
            } else if (Array.isArray(obj.gpos)) {
              dataArray = obj.gpos as Record<string, unknown>[]
            } else {
              return emptyResult(
                "Could not find data array in JSON. Expected { data: [...] } or a top-level array.",
              )
            }
          } else {
            return emptyResult(
              "JSON root must be an array or object with a data array.",
            )
          }

          if (dataArray.length === 0) {
            return emptyResult("BloodHound JSON contains an empty data array.")
          }

          // Detect or use specified type
          const dataType = requestedType ?? detectDataType(dataArray[0]!)
          if (!dataType) {
            return emptyResult(
              "Could not auto-detect BloodHound data type. Specify data_type parameter (computers, users, groups, domains, gpos).",
            )
          }

          const summaries: ParseSummary[] = []
          let totalFindings = 0
          let hostsAdded = 0
          let vulnsAdded = 0
          const oosHosts: string[] = []

          // ---------- Process by type ----------

          if (dataType === "computers") {
            const computers = parseComputers(dataArray)
            const findings: string[] = []
            const stateUpdates: string[] = []
            const enabled = computers.filter((c) => c.enabled)

            const unconstrainedDelegation = enabled.filter((c) => c.unconstraineddelegation)
            if (unconstrainedDelegation.length > 0) {
              findings.push(
                `[HIGH] ${unconstrainedDelegation.length} computer(s) with unconstrained delegation: ${unconstrainedDelegation.map((c) => c.name).join(", ")}`,
              )
              totalFindings += unconstrainedDelegation.length
            }

            const noLaps = enabled.filter((c) => !c.haslaps)
            if (noLaps.length > 0) {
              findings.push(
                `[MEDIUM] ${noLaps.length} computer(s) without LAPS`,
              )
            }

            const osSummary = new Map<string, number>()
            for (const c of enabled) {
              const os = c.operatingsystem ?? "Unknown"
              osSummary.set(os, (osSummary.get(os) ?? 0) + 1)
            }
            for (const [os, count] of osSummary) {
              findings.push(`OS: ${os} (${count})`)
            }

            if (shouldUpdate) {
              const state = yield* store.get()
              const scopeEnabled = enabled.filter((c) => {
                if (!c.name) return false
                const hostKey = c.name.toUpperCase()
                if (state && state.scope.targets.length > 0 && state.mode !== "free") {
                  const result = ScopeMatcher.checkScope(hostKey, state.scope)
                  if (!result.inScope && c.name) {
                    const byName = ScopeMatcher.checkScope(c.name, state.scope)
                    if (!byName.inScope) { oosHosts.push(c.name); return false }
                  }
                }
                return true
              })
              for (const c of scopeEnabled) {
                if (!c.name) continue
                const hostKey = c.name.toUpperCase()
                const domainName = c.domain ?? c.name.split(".").slice(1).join(".")

                yield* store.addHost(hostKey, {
                  ip: hostKey,
                  hostname: c.name,
                  os: c.operatingsystem ?? undefined,
                  domain_info: {
                    domain: domainName || undefined,
                    computer_account: c.name,
                  },
                })
                hostsAdded++
                stateUpdates.push(`Added host: ${c.name}`)

                if (state) {
                  yield* events.publish(PentestEvent.HostDiscovered, {
                    timestamp: Date.now(),
                    engagementID: state.id,
                    ip: hostKey,
                    hostname: c.name,
                    serviceCount: 0,
                  })
                }

                // Flag unconstrained delegation as vuln
                if (c.unconstraineddelegation) {
                  const udEvidence = `BloodHound: unconstraineddelegation=true, ObjectIdentifier=${c.objectid}`
                  yield* store.addVuln(hostKey, {
                    id: `unconstrained-delegation-${hostnameToIp(c.name)}`,
                    title: `Unconstrained Delegation: ${c.name}`,
                    severity: "high",
                    status: "confirmed",
                    confidence: 0.9,
                    description:
                      "Computer account has unconstrained delegation enabled. An attacker who compromises this host can extract TGTs from memory for any user that authenticates to it.",
                    evidence: udEvidence,
                    evidence_items: [{
                      tool: "bloodhound",
                      output: udEvidence,
                      timestamp: new Date().toISOString(),
                      confidence: 0.9,
                    }],
                    references: ["https://attack.mitre.org/techniques/T1558/"],
                  })
                  vulnsAdded++

                  if (state) {
                    yield* events.publish(PentestEvent.VulnFound, {
                      timestamp: Date.now(),
                      engagementID: state.id,
                      hostIp: hostKey,
                      title: `Unconstrained Delegation: ${c.name}`,
                      severity: "high",
                      status: "confirmed",
                    })
                  }
                }
              }
            }

            summaries.push({
              type: "computers",
              totalItems: computers.length,
              findings,
              stateUpdates,
            })
          }

          if (dataType === "users") {
            const users = parseUsers(dataArray)
            const findings: string[] = []
            const stateUpdates: string[] = []
            const enabled = users.filter((u) => u.enabled)

            const kerberoastable = enabled.filter((u) => u.hasspn)
            if (kerberoastable.length > 0) {
              findings.push(
                `[HIGH] ${kerberoastable.length} kerberoastable user(s): ${kerberoastable.map((u) => u.name).join(", ")}`,
              )
              totalFindings += kerberoastable.length
            }

            const asrepRoastable = enabled.filter((u) => u.dontreqpreauth)
            if (asrepRoastable.length > 0) {
              findings.push(
                `[HIGH] ${asrepRoastable.length} AS-REP roastable user(s): ${asrepRoastable.map((u) => u.name).join(", ")}`,
              )
              totalFindings += asrepRoastable.length
            }

            const adminUsers = enabled.filter((u) => u.admincount)
            if (adminUsers.length > 0) {
              findings.push(
                `[INFO] ${adminUsers.length} high-privilege account(s) (admincount=true): ${adminUsers.map((u) => u.name).join(", ")}`,
              )
            }

            findings.push(
              `Total: ${users.length} users (${enabled.length} enabled, ${users.length - enabled.length} disabled)`,
            )

            if (shouldUpdate) {
              const state = yield* store.get()

              // Kerberoastable users -> vulns on a domain-level host or first DC
              for (const u of kerberoastable) {
                const domainName = u.domain ?? u.name.split("@").pop() ?? "UNKNOWN"
                const hostKey = domainName.toUpperCase()

                // Ensure a host entry exists for the domain
                yield* store.addHost(hostKey, {
                  ip: hostKey,
                  hostname: domainName,
                  domain_info: { domain: domainName },
                })

                const spns =
                  u.serviceprincipalnames && u.serviceprincipalnames.length > 0
                    ? u.serviceprincipalnames.join(", ")
                    : "SPN set"
                const safeUsername = u.name.toLowerCase().replace(/[^a-z0-9_@.-]/g, "_")

                const kerbEvidence = `BloodHound: hasspn=true, SPNs: ${spns}, ObjectIdentifier=${u.objectid}`
                yield* store.addVuln(hostKey, {
                  id: `kerberoast-${safeUsername}`,
                  title: `Kerberoastable Service Account: ${u.name}`,
                  severity: "high",
                  status: "confirmed",
                  confidence: 0.9,
                  description: `User ${u.name} has SPNs set and is kerberoastable. Request a TGS ticket and crack offline to recover the plaintext password.`,
                  evidence: kerbEvidence,
                  evidence_items: [{
                    tool: "bloodhound",
                    output: kerbEvidence,
                    timestamp: new Date().toISOString(),
                    confidence: 0.9,
                  }],
                  references: ["https://attack.mitre.org/techniques/T1558/003/"],
                })
                vulnsAdded++
                stateUpdates.push(`Added vuln: Kerberoastable ${u.name}`)

                if (state) {
                  yield* events.publish(PentestEvent.VulnFound, {
                    timestamp: Date.now(),
                    engagementID: state.id,
                    hostIp: hostKey,
                    title: `Kerberoastable Service Account: ${u.name}`,
                    severity: "high",
                    status: "confirmed",
                  })
                }
              }

              // AS-REP roastable users -> vulns
              for (const u of asrepRoastable) {
                const domainName = u.domain ?? u.name.split("@").pop() ?? "UNKNOWN"
                const hostKey = domainName.toUpperCase()

                yield* store.addHost(hostKey, {
                  ip: hostKey,
                  hostname: domainName,
                  domain_info: { domain: domainName },
                })

                const safeUsername = u.name.toLowerCase().replace(/[^a-z0-9_@.-]/g, "_")

                const asrepEvidence = `BloodHound: dontreqpreauth=true, ObjectIdentifier=${u.objectid}`
                yield* store.addVuln(hostKey, {
                  id: `asrep-roast-${safeUsername}`,
                  title: `AS-REP Roastable Account: ${u.name}`,
                  severity: "high",
                  status: "confirmed",
                  confidence: 0.9,
                  description: `User ${u.name} does not require Kerberos pre-authentication. Request an AS-REP and crack offline.`,
                  evidence: asrepEvidence,
                  evidence_items: [{
                    tool: "bloodhound",
                    output: asrepEvidence,
                    timestamp: new Date().toISOString(),
                    confidence: 0.9,
                  }],
                  references: ["https://attack.mitre.org/techniques/T1558/004/"],
                })
                vulnsAdded++
                stateUpdates.push(`Added vuln: AS-REP roastable ${u.name}`)

                if (state) {
                  yield* events.publish(PentestEvent.VulnFound, {
                    timestamp: Date.now(),
                    engagementID: state.id,
                    hostIp: hostKey,
                    title: `AS-REP Roastable Account: ${u.name}`,
                    severity: "high",
                    status: "confirmed",
                  })
                }
              }
            }

            summaries.push({
              type: "users",
              totalItems: users.length,
              findings,
              stateUpdates,
            })
          }

          if (dataType === "groups") {
            const groups = parseGroups(dataArray)
            const findings: string[] = []
            const stateUpdates: string[] = []

            const adminGroups = groups.filter((g) => g.admincount)
            const largeMemberGroups = groups.filter((g) => g.members.length > 50)

            findings.push(
              `Total: ${groups.length} groups, ${adminGroups.length} with admincount=true`,
            )

            if (largeMemberGroups.length > 0) {
              findings.push(
                `[INFO] ${largeMemberGroups.length} group(s) with >50 members`,
              )
            }

            // Extract domain admin group members
            const daGroups = groups.filter((g) => {
              const name = g.name.toUpperCase()
              return (
                name.includes("DOMAIN ADMINS") ||
                name.includes("ENTERPRISE ADMINS") ||
                name.includes("SCHEMA ADMINS") ||
                name.includes("ADMINISTRATORS")
              )
            })

            if (daGroups.length > 0) {
              for (const g of daGroups) {
                const userMembers = g.members.filter((m) => m.ObjectType === "User")
                findings.push(
                  `[INFO] ${g.name}: ${g.members.length} members (${userMembers.length} users)`,
                )
              }
            }

            if (shouldUpdate) {
              // Extract domain admins for domain state
              const domainAdmins: string[] = []
              for (const g of daGroups) {
                for (const m of g.members) {
                  if (m.ObjectType === "User") {
                    domainAdmins.push(m.ObjectIdentifier)
                  }
                }
              }
              if (domainAdmins.length > 0) {
                stateUpdates.push(
                  `Identified ${domainAdmins.length} domain admin account(s) from privileged groups`,
                )
              }

              // Auto-create MEMBER_OF relationships
              for (const g of groups) {
                for (const m of g.members) {
                  yield* store.addRelationship({
                    source_type: m.ObjectType === "User" ? "user" : m.ObjectType === "Group" ? "group" : "host",
                    source_id: m.ObjectIdentifier,
                    rel_type: "MEMBER_OF",
                    target_type: "group",
                    target_id: g.objectid,
                    metadata: g.name,
                  })
                }
                // DA/EA groups → ADMIN_OF relationships
                if (g.admincount) {
                  for (const m of g.members) {
                    if (m.ObjectType === "User") {
                      yield* store.addRelationship({
                        source_type: "user",
                        source_id: m.ObjectIdentifier,
                        rel_type: "ADMIN_OF",
                        target_type: "domain",
                        target_id: g.name.split("@").pop() ?? g.name,
                        metadata: `via ${g.name}`,
                      })
                    }
                  }
                }
              }
            }

            summaries.push({
              type: "groups",
              totalItems: groups.length,
              findings,
              stateUpdates,
            })
          }

          if (dataType === "domains") {
            const domains = parseDomains(dataArray)
            const findings: string[] = []
            const stateUpdates: string[] = []

            for (const d of domains) {
              findings.push(
                `Domain: ${d.name}${d.functionallevel ? ` (${d.functionallevel})` : ""}`,
              )

              if (d.trusts.length > 0) {
                for (const t of d.trusts) {
                  const dir = trustDirectionLabel(t.TrustDirection)
                  const type = trustTypeLabel(t.TrustType)
                  const transitive = t.IsTransitive ? "transitive" : "non-transitive"
                  findings.push(
                    `  Trust: ${t.TargetDomainName} [${dir}, ${type}, ${transitive}]`,
                  )

                  if (dir === "bidirectional") {
                    findings.push(
                      `  [MEDIUM] Bidirectional trust with ${t.TargetDomainName} — potential lateral movement path`,
                    )
                    totalFindings++
                  }
                }
              }
            }

            if (shouldUpdate) {
              for (const d of domains) {
                const domainName = d.domain ?? d.name
                const trusts = d.trusts.map((t) => ({
                  target_domain: t.TargetDomainName,
                  trust_direction: trustDirectionLabel(t.TrustDirection),
                  trust_type: trustTypeLabel(t.TrustType),
                  is_transitive: t.IsTransitive,
                }))

                yield* store.setDomain({
                  domain_name: domainName,
                  trusts,
                })
                stateUpdates.push(`Set domain: ${domainName} with ${trusts.length} trust(s)`)

                // Auto-create TRUSTS relationships
                for (const t of d.trusts) {
                  yield* store.addRelationship({
                    source_type: "domain",
                    source_id: domainName,
                    rel_type: "TRUSTS",
                    target_type: "domain",
                    target_id: t.TargetDomainName,
                    metadata: `${trustDirectionLabel(t.TrustDirection)} ${trustTypeLabel(t.TrustType)}`,
                  })
                }

                // Add bidirectional trusts as vulns
                const state = yield* store.get()
                for (const t of d.trusts) {
                  const dir = trustDirectionLabel(t.TrustDirection)
                  if (dir === "bidirectional") {
                    const hostKey = domainName.toUpperCase()
                    yield* store.addHost(hostKey, {
                      ip: hostKey,
                      hostname: domainName,
                      domain_info: { domain: domainName },
                    })

                    const trustEvidence = `BloodHound: TrustDirection=${t.TrustDirection}, TrustType=${t.TrustType}, IsTransitive=${t.IsTransitive}`
                    yield* store.addVuln(hostKey, {
                      id: `bidirectional-trust-${t.TargetDomainName.toLowerCase().replace(/[^a-z0-9.-]/g, "_")}`,
                      title: `Bidirectional Domain Trust: ${t.TargetDomainName}`,
                      severity: "medium",
                      status: "confirmed",
                      confidence: 0.9,
                      description: `Bidirectional trust exists between ${domainName} and ${t.TargetDomainName}. This may allow lateral movement across domain boundaries.`,
                      evidence: trustEvidence,
                      evidence_items: [{
                        tool: "bloodhound",
                        output: trustEvidence,
                        timestamp: new Date().toISOString(),
                        confidence: 0.9,
                      }],
                      references: ["https://attack.mitre.org/techniques/T1482/"],
                    })
                    vulnsAdded++

                    if (state) {
                      yield* events.publish(PentestEvent.VulnFound, {
                        timestamp: Date.now(),
                        engagementID: state.id,
                        hostIp: hostKey,
                        title: `Bidirectional Domain Trust: ${t.TargetDomainName}`,
                        severity: "medium",
                        status: "confirmed",
                      })
                    }
                  }
                }
              }
            }

            summaries.push({
              type: "domains",
              totalItems: domains.length,
              findings,
              stateUpdates,
            })
          }

          if (dataType === "gpos") {
            const gpos = parseGPOs(dataArray)
            const findings: string[] = []
            const stateUpdates: string[] = []

            findings.push(`Total: ${gpos.length} GPO(s)`)

            const withPath = gpos.filter((g) => g.gpcpath)
            if (withPath.length > 0) {
              findings.push(`GPOs with GPC paths: ${withPath.length}`)
              for (const g of withPath) {
                findings.push(`  ${g.name}: ${g.gpcpath}`)
              }
            }

            if (shouldUpdate) {
              const gpoNames = gpos.map((g) => g.name).filter(Boolean)
              if (gpoNames.length > 0) {
                yield* store.updateDomain({ gpo_names: gpoNames })
                stateUpdates.push(`Updated domain with ${gpoNames.length} GPO name(s)`)
              }
            }

            summaries.push({
              type: "gpos",
              totalItems: gpos.length,
              findings,
              stateUpdates,
            })
          }

          // Persist to disk
          if (shouldUpdate) {
            const updatedState = yield* store.get()
            if (updatedState) yield* store.save(updatedState)
          }

          let output = formatOutput(summaries, shouldUpdate)
          const totalItems = summaries.reduce((s, x) => s + x.totalItems, 0)

          if (oosHosts.length > 0) {
            output += `\n[SCOPE] Filtered ${oosHosts.length} out-of-scope computer(s): ${oosHosts.join(", ")}. Not added to engagement state.`
          }

          return {
            title: `bloodhound: ${dataType}, ${totalItems} items, ${totalFindings} findings, ${vulnsAdded} vulns`,
            metadata: {
              data_type: dataType,
              total_items: totalItems,
              findings: totalFindings,
              hosts_added: hostsAdded,
              vulns_added: vulnsAdded,
              auto_updated: shouldUpdate,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
