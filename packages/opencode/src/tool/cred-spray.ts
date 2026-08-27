import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import type { EngagementSchema } from "@auditcode/core/engagement/schema"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import DESCRIPTION from "./cred-spray.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["plan", "suggest"]).annotate({
    description: "plan: generate spray commands. suggest: check if new creds should be sprayed.",
  }),
  credential_id: Schema.optional(Schema.String).annotate({
    description: "Credential ID from engagement state",
  }),
  username: Schema.optional(Schema.String).annotate({
    description: "Username (alternative to credential_id)",
  }),
  password: Schema.optional(Schema.String).annotate({
    description: "Password or hash (alternative to credential_id)",
  }),
  service_filter: Schema.optional(Schema.String).annotate({
    description: "Limit to service types: smb,winrm,rdp,ssh,mssql,mysql,postgresql,ftp,web",
  }),
})

interface SprayTarget {
  host: string
  port: number
  service: string
  command: string
}

const SERVICE_PORT_MAP: Record<string, string> = {
  "microsoft-ds": "smb",
  "netbios-ssn": "smb",
  smb: "smb",
  ssh: "ssh",
  ftp: "ftp",
  "ms-sql-s": "mssql",
  mssql: "mssql",
  mysql: "mysql",
  postgresql: "postgresql",
  postgres: "postgresql",
  rdp: "rdp",
  "ms-wbt-server": "rdp",
  "wsman": "winrm",
  http: "web",
  https: "web",
  "http-proxy": "web",
}

const PORT_SERVICE_MAP: Record<number, string> = {
  22: "ssh",
  21: "ftp",
  445: "smb",
  139: "smb",
  3389: "rdp",
  5985: "winrm",
  5986: "winrm",
  1433: "mssql",
  3306: "mysql",
  5432: "postgresql",
  80: "web",
  443: "web",
  8080: "web",
  8443: "web",
}

const DEFAULT_PORTS: Record<string, number> = {
  smb: 445,
  ssh: 22,
  ftp: 21,
  rdp: 3389,
  winrm: 5985,
  mssql: 1433,
  mysql: 3306,
  postgresql: 5432,
  web: 80,
}

const DOMAIN_AUTH_SERVICES = new Set(["smb", "winrm", "rdp", "mssql"])

export function shq(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'"
}

function resolveService(svc: EngagementSchema.Service): string | undefined {
  if (svc.service) {
    const mapped = SERVICE_PORT_MAP[svc.service.toLowerCase()]
    if (mapped) return mapped
  }
  return PORT_SERVICE_MAP[svc.port]
}

export function buildCommand(service: string, host: string, port: number, username: string, value: string, isHash: boolean): string {
  const u = username
  const h = shq(host)
  const uq = shq(u)
  const vq = shq(value)
  const defaultPort = DEFAULT_PORTS[service] ?? 0
  const nonStandard = port !== defaultPort

  switch (service) {
    case "smb": {
      const pf = nonStandard ? ` --port ${port}` : ""
      return isHash
        ? `netexec smb ${h} -u ${uq} -H ${vq}${pf}`
        : `netexec smb ${h} -u ${uq} -p ${vq}${pf}`
    }
    case "winrm": {
      const pf = nonStandard ? ` --port ${port}` : ""
      return isHash
        ? `netexec winrm ${h} -u ${uq} -H ${vq}${pf}`
        : `netexec winrm ${h} -u ${uq} -p ${vq}${pf}`
    }
    case "rdp": {
      const pf = nonStandard ? ` --port ${port}` : ""
      return isHash
        ? `netexec rdp ${h} -u ${uq} -H ${vq}${pf}`
        : `netexec rdp ${h} -u ${uq} -p ${vq}${pf}`
    }
    case "ssh": {
      const pf = nonStandard ? ` --port ${port}` : ""
      return `netexec ssh ${h} -u ${uq} -p ${vq}${pf}`
    }
    case "mssql": {
      const pf = nonStandard ? ` --port ${port}` : ""
      return isHash
        ? `netexec mssql ${h} -u ${uq} -H ${vq}${pf}`
        : `netexec mssql ${h} -u ${uq} -p ${vq}${pf}`
    }
    case "mysql":
      return `mysql -h ${h} -P ${port} -u ${uq} -p${vq} -e 'SELECT 1' 2>&1 | head -5`
    case "postgresql":
      return `PGPASSWORD=${vq} psql -h ${h} -p ${port} -U ${uq} -c 'SELECT 1' 2>&1 | head -5`
    case "ftp":
      return `curl -s -u ${shq(u + ":" + value)} ftp://${shq(host)}:${port}/ 2>&1 | head -5`
    case "web": {
      const scheme = port === 443 || port === 8443 ? "https" : "http"
      return `curl -sk -o /dev/null -w '%{http_code}' -u ${shq(u + ":" + value)} ${scheme}://${shq(host)}:${port}/`
    }
    default:
      return `# Unknown service: ${service} on ${shq(host)}`
  }
}

export function isNtlmHash(value: string): boolean {
  return /^[a-fA-F0-9]{32}(:[a-fA-F0-9]{32})?$/.test(value)
}

export const CredSprayTool = Tool.define(
  "cred_spray",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) {
            return { title: "Error", metadata: {}, output: "No engagement loaded." }
          }

          let username: string
          let value: string
          let credType: string

          if (params.credential_id) {
            const cred = state.credentials[params.credential_id]
            if (!cred) {
              const available = Object.keys(state.credentials)
              return {
                title: "Error",
                metadata: {},
                output: `Credential "${params.credential_id}" not found.${available.length > 0 ? ` Available: ${available.join(", ")}` : ""}`,
              }
            }
            username = cred.username ?? ""
            value = cred.value ?? ""
            credType = cred.cred_type ?? "password"
          } else if (params.username && params.password) {
            username = params.username
            value = params.password
            credType = isNtlmHash(params.password) ? "ntlm_hash" : "password"
          } else {
            return {
              title: "Error",
              metadata: {},
              output: "Error: provide either credential_id or both username and password.",
            }
          }

          if (!username || !value) {
            return { title: "Error", metadata: {}, output: "Credential has no username or value." }
          }

          const isHash = credType === "ntlm_hash" || credType === "hash"
            || (credType !== "password" && isNtlmHash(value))
          const serviceFilter = params.service_filter
            ? new Set(params.service_filter.split(",").map((s) => s.trim().toLowerCase()))
            : undefined

          const hasScope = state.scope.targets.length > 0
          const targets: SprayTarget[] = []
          const seen = new Set<string>()
          for (const [ip, host] of Object.entries(state.hosts)) {
            if (hasScope && state.mode !== "free") {
              const scopeResult = ScopeMatcher.checkScope(ip, state.scope)
              if (!scopeResult.inScope) continue
            }

            for (const svc of host.services) {
              const resolved = resolveService(svc)
              if (!resolved) continue
              if (serviceFilter && !serviceFilter.has(resolved)) continue

              const dedup = `${ip}:${resolved}`
              if (seen.has(dedup)) continue
              seen.add(dedup)

              const alreadyHasAccess = host.access.some(
                (a) => a.username === username,
              )
              if (alreadyHasAccess) continue

              targets.push({
                host: ip,
                port: svc.port,
                service: resolved,
                command: buildCommand(resolved, ip, svc.port, username, value, isHash),
              })
            }
          }

          if (params.action === "suggest") {
            if (targets.length === 0) {
              return {
                title: "No spray targets",
                metadata: { count: 0 },
                output: `Credential ${username} has no untested service combinations. All discovered hosts either have no matching services or already have access with this username.`,
              }
            }
            const byService: Record<string, number> = {}
            for (const t of targets) {
              byService[t.service] = (byService[t.service] ?? 0) + 1
            }
            const breakdown = Object.entries(byService)
              .map(([svc, count]) => `${svc}:${count}`)
              .join(", ")
            return {
              title: `Spray: ${targets.length} targets`,
              metadata: { count: targets.length, services: byService },
              output: `Credential ${username} (${credType}) can be tested against ${targets.length} service combinations (${breakdown}). Run cred_spray with action:"plan" to get commands.`,
            }
          }

          // action === "plan"
          if (targets.length === 0) {
            return {
              title: "No spray targets",
              metadata: { count: 0 },
              output: `No untested service combinations for ${username}. All hosts either lack matching services or already have access with this username.`,
            }
          }

          const grouped: Record<string, SprayTarget[]> = {}
          for (const t of targets) {
            const key = t.service
            if (!grouped[key]) grouped[key] = []
            grouped[key]!.push(t)
          }

          const warnings: string[] = []

          const lockoutThreshold = state.domain?.password_policy?.lockout_threshold
          if (lockoutThreshold) {
            const domainAuthHosts = new Set(
              targets.filter((t) => DOMAIN_AUTH_SERVICES.has(t.service)).map((t) => t.host),
            )
            if (domainAuthHosts.size >= lockoutThreshold) {
              warnings.push(
                `LOCKOUT RISK: ${domainAuthHosts.size} domain-auth targets, lockout threshold = ${lockoutThreshold}.`,
                `Spraying this plan will likely lock out the account "${username}".`,
                `Instead: spray ONE password across MANY users, not one user across many hosts.`,
                `Or split into batches of ${lockoutThreshold - 1} hosts max with delays between batches.`,
                "",
              )
            }
          }

          const lines: string[] = [
            ...warnings,
            `Spray plan for ${username} (${credType}${isHash ? " — using hash" : ""}):`,
            `${targets.length} combinations across ${Object.keys(grouped).length} service types`,
            "",
          ]

          for (const [service, group] of Object.entries(grouped)) {
            lines.push(`--- ${service.toUpperCase()} (${group.length}) ---`)
            for (const t of group) {
              lines.push(t.command)
            }
            lines.push("")
          }

          lines.push("Execute these commands and record results with state_update (add_access for successes, add_attack_step for attempts).")

          return {
            title: `Spray: ${targets.length} targets`,
            metadata: {
              count: targets.length,
              username,
              services: Object.keys(grouped),
              ...(warnings.length > 0 ? { lockout_warning: true } : {}),
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)
