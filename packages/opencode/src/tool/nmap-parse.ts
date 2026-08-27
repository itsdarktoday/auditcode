import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import type { EngagementSchema } from "@auditcode/core/engagement/schema"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import { FSUtil } from "@auditcode/core/fs-util"
import { Parser } from "htmlparser2"
import DESCRIPTION from "./nmap-parse.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  input: Schema.String.annotate({
    description: "Nmap output text (XML/greppable) or file path to read",
  }),
  format: Schema.optional(Schema.Literals(["xml", "greppable", "auto"])).annotate({
    description: "Input format. Default: auto-detect from content",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Add discovered hosts/services to engagement state (default: true)",
  }),
})

interface ParsedService {
  port: number
  protocol: string
  service: string
  version: string
  state: string
}

interface ParsedHost {
  ip: string
  hostname?: string
  os?: string
  services: ParsedService[]
}

function looksLikeFilePath(input: string): boolean {
  const trimmed = input.trimStart()
  if (trimmed.startsWith("/") || trimmed.startsWith("./") || trimmed.startsWith("~/")) return true
  if (/\.(xml|gnmap|nmap)$/i.test(trimmed.split("\n")[0]!.trim())) return true
  return false
}

function detectFormat(content: string): "xml" | "greppable" {
  if (content.includes("<?xml") || content.includes("<nmaprun")) return "xml"
  if (/^Host:\s+\S+.*Ports:/m.test(content)) return "greppable"
  // Default: try XML since it's more structured
  return "xml"
}

function parseXml(content: string): ParsedHost[] {
  const hosts: ParsedHost[] = []
  let currentHost: ParsedHost | undefined
  let inPort = false
  let currentPort: Partial<ParsedService> = {}

  const parser = new Parser(
    {
      onopentag(name, attribs) {
        const tag = name.toLowerCase()
        if (tag === "host") {
          currentHost = { ip: "", services: [] }
          return
        }
        if (!currentHost) return

        if (tag === "address") {
          const addrType = (attribs["addrtype"] ?? "").toLowerCase()
          if (addrType === "ipv4" || addrType === "ipv6") {
            currentHost.ip = attribs["addr"] ?? ""
          }
          return
        }

        if (tag === "hostname") {
          const hname = attribs["name"]
          if (hname && !currentHost.hostname) {
            currentHost.hostname = hname
          }
          return
        }

        if (tag === "port") {
          inPort = true
          currentPort = {
            protocol: attribs["protocol"] ?? "tcp",
            port: Number(attribs["portid"] ?? 0),
          }
          return
        }

        if (tag === "state" && inPort) {
          currentPort.state = attribs["state"] ?? ""
          return
        }

        if (tag === "service" && inPort) {
          const parts: string[] = []
          if (attribs["product"]) parts.push(attribs["product"])
          if (attribs["version"]) parts.push(attribs["version"])
          if (attribs["extrainfo"]) parts.push(attribs["extrainfo"])
          currentPort.service = attribs["name"] ?? ""
          currentPort.version = parts.join(" ")
          return
        }

        if (tag === "osmatch") {
          const osName = attribs["name"]
          if (osName && !currentHost.os) {
            currentHost.os = osName
          }
          return
        }
      },

      onclosetag(name) {
        const tag = name.toLowerCase()
        if (tag === "port" && inPort && currentHost) {
          if (currentPort.state === "open" || currentPort.state === "open|filtered") {
            currentHost.services.push({
              port: currentPort.port ?? 0,
              protocol: currentPort.protocol ?? "tcp",
              service: currentPort.service ?? "",
              version: currentPort.version ?? "",
              state: currentPort.state,
            })
          }
          inPort = false
          currentPort = {}
          return
        }

        if (tag === "host" && currentHost) {
          if (currentHost.ip) {
            hosts.push(currentHost)
          }
          currentHost = undefined
          return
        }
      },
    },
    { xmlMode: true },
  )

  parser.write(content)
  parser.end()

  return hosts
}

function parseGreppable(content: string): ParsedHost[] {
  const hosts: ParsedHost[] = []
  const hostPattern = /^Host:\s+(\S+)\s*(?:\(([^)]*)\))?\s+Ports:\s+(.+)/

  for (const line of content.split("\n")) {
    const match = hostPattern.exec(line.trim())
    if (!match) continue

    const ip = match[1]!
    const hostname = match[2] || undefined
    const portsStr = match[3]!

    const services: ParsedService[] = []
    // Port entries separated by comma+space, each: port/state/protocol//service//version/
    for (const portEntry of portsStr.split(/,\s*/)) {
      const parts = portEntry.trim().split("/")
      if (parts.length < 3) continue

      const port = Number(parts[0])
      const state = parts[1] ?? ""
      const protocol = parts[2] ?? "tcp"
      // parts[3] is empty, parts[4] is service name, parts[5] is empty, parts[6] is version
      const service = parts[4] ?? ""
      const version = parts[6] ?? ""

      if (state === "open" || state === "open|filtered") {
        services.push({
          port: isNaN(port) ? 0 : port,
          protocol,
          service,
          version,
          state,
        })
      }
    }

    hosts.push({ ip, hostname: hostname || undefined, services })
  }

  return hosts
}

const SERVICE_SKILL_MAP: Record<string, string> = {
  http: "svc-web-server",
  https: "svc-web-server",
  "http-proxy": "svc-web-server",
  ssh: "svc-ssh",
  ftp: "svc-ftp",
  smtp: "svc-mail",
  pop3: "svc-mail",
  imap: "svc-mail",
  smb: "svc-smb",
  "microsoft-ds": "svc-smb",
  "netbios-ssn": "svc-smb",
  mysql: "svc-database",
  postgresql: "svc-database",
  "ms-sql-s": "svc-database",
  redis: "svc-database",
  mongodb: "svc-database",
  dns: "svc-dns",
  domain: "svc-dns",
  docker: "svc-docker-k8s",
  "kubernetes-api": "svc-docker-k8s",
  jenkins: "svc-cicd",
  gitlab: "svc-cicd",
}

function suggestSkills(hosts: ParsedHost[]): string[] {
  const skills = new Set<string>()
  for (const host of hosts) {
    for (const svc of host.services) {
      const skill = SERVICE_SKILL_MAP[svc.service.toLowerCase()]
      if (skill) skills.add(skill)
    }
  }
  return [...skills]
}

function formatOutput(hosts: ParsedHost[], autoUpdated: boolean, serviceCount: number): string {
  const lines: string[] = []
  lines.push(`Parsed ${hosts.length} host${hosts.length !== 1 ? "s" : ""}, ${serviceCount} service${serviceCount !== 1 ? "s" : ""} from nmap output`)
  lines.push("")

  for (const host of hosts) {
    const parts = [host.ip]
    if (host.hostname) parts.push(`(${host.hostname})`)
    if (host.os) parts.push(`-- ${host.os}`)
    lines.push(parts.join(" "))

    if (host.services.length === 0) {
      lines.push("  (no open ports)")
    } else {
      for (const svc of host.services) {
        const portStr = `${svc.port}/${svc.protocol}`.padEnd(10)
        const stateStr = svc.state.padEnd(6)
        const svcStr = (svc.service || "unknown").padEnd(12)
        const verStr = svc.version || ""
        lines.push(`  ${portStr} ${stateStr} ${svcStr} ${verStr}`.trimEnd())
      }
    }
    lines.push("")
  }

  if (autoUpdated) {
    lines.push(`[Auto-updated engagement state: ${hosts.length} host${hosts.length !== 1 ? "s" : ""}, ${serviceCount} service${serviceCount !== 1 ? "s" : ""}]`)
  } else {
    lines.push("[Engagement state not updated (auto_update=false)]")
  }

  return lines.join("\n")
}

export const NmapParseTool = Tool.define(
  "nmap_parse",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const fs = yield* FSUtil.Service
    const events = yield* EventV2Bridge.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { input: string; format?: "xml" | "greppable" | "auto"; auto_update?: boolean },
        _ctx: Tool.Context,
      ) =>
        Effect.gen(function* () {
          let content = params.input
          const shouldUpdate = params.auto_update !== false

          // Resolve file path if input looks like a path
          if (looksLikeFilePath(content.trim())) {
            const filePath = content.trim()
            const exists = yield* fs.existsSafe(filePath)
            if (exists) {
              content = yield* fs.readFileString(filePath)
            }
            // If file doesn't exist, treat input as raw text
          }

          // Detect or use specified format
          const format = params.format === "auto" || !params.format ? detectFormat(content) : params.format

          // Parse
          let hosts: ParsedHost[]
          if (format === "xml") {
            hosts = parseXml(content)
            // Fallback to greppable if XML produced nothing
            if (hosts.length === 0 && /^Host:\s+\S+.*Ports:/m.test(content)) {
              hosts = parseGreppable(content)
            }
          } else {
            hosts = parseGreppable(content)
          }

          if (hosts.length === 0) {
            return {
              title: "nmap parse",
              metadata: { hosts: 0, services: 0, format, auto_updated: false },
              output: "No hosts found in the provided nmap output. Verify the input format is XML or greppable (-oX or -oG).",
            }
          }

          const totalServices = hosts.reduce((sum, h) => sum + h.services.length, 0)
          const oosHosts: string[] = []

          // Auto-update engagement state
          if (shouldUpdate) {
            const state = yield* store.get()
            const inScopeHosts = hosts.filter((host) => {
              if (state && state.scope.targets.length > 0 && state.mode !== "free") {
                const result = ScopeMatcher.checkScope(host.ip, state.scope)
                if (!result.inScope) { oosHosts.push(host.ip); return false }
              }
              return true
            })
            for (const host of inScopeHosts) {
              const services: EngagementSchema.Service[] = host.services.map((s) => ({
                port: s.port,
                protocol: s.protocol,
                service: s.service,
                version: s.version,
                state: s.state,
                banner: "",
              }))

              yield* store.addHost(host.ip, {
                ip: host.ip,
                ...(host.hostname ? { hostname: host.hostname } : {}),
                ...(host.os ? { os: host.os } : {}),
                services,
              })

              if (state) {
                yield* events.publish(PentestEvent.HostDiscovered, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  ip: host.ip,
                  hostname: host.hostname,
                  serviceCount: host.services.length,
                })
                for (const svc of host.services) {
                  yield* events.publish(PentestEvent.ServiceFound, {
                    timestamp: Date.now(),
                    engagementID: state.id,
                    hostIp: host.ip,
                    port: svc.port,
                    service: svc.service || undefined,
                    version: svc.version || undefined,
                  })
                }
              }
            }

            // NOTE: we deliberately do NOT synthesize REACHABLE_FROM edges here.
            // Appearing together in one nmap scan means the scanner reached each host,
            // NOT that the hosts can reach each other. Fabricating all-pairs reachability
            // poisoned attack_path_suggest (Dijkstra/Yen over invented edges). Reachability
            // is recorded only from OBSERVED evidence — a successful connection/route/pivot
            // (e.g. cme_parse AUTHENTICATES_TO, an explicit state_update add_relationship,
            // or bloodhound edges) — never inferred from co-scanning.

            // Persist to disk
            const updatedState = yield* store.get()
            if (updatedState) yield* store.save(updatedState)
          }

          const recommended = suggestSkills(hosts)
          let output = formatOutput(hosts, shouldUpdate, totalServices)
          if (recommended.length > 0) {
            output += `\n\nRelevant service skills available: ${recommended.map((s) => `"${s}"`).join(", ")}. Load via the skill tool for service-specific attack techniques.`
          }

          if (shouldUpdate && hosts.length > 0) {
            output += `\n\n[Auto-critic] New hosts discovered. After enumeration, spawn "critic" subagent to validate any findings.`
          }

          if (oosHosts.length > 0) {
            output += `\n\n[SCOPE] Filtered ${oosHosts.length} out-of-scope host(s): ${oosHosts.join(", ")}. Not added to engagement state.`
          }

          return {
            title: `nmap: ${hosts.length} hosts, ${totalServices} services`,
            metadata: {
              hosts: hosts.length,
              services: totalServices,
              format,
              auto_updated: shouldUpdate,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
