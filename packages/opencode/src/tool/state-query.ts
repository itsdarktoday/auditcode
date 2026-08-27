import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { BackgroundJob } from "@/background/job"
import DESCRIPTION from "./state-query.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  query_type: Schema.Literals([
    "summary",
    "contracts",
    "contract",
    "invariants",
    "actors",
    "pocs",
    "hosts",
    "vulns",
    "creds",
    "scope",
    "phase",
    "flags",
    "tasks",
    "host",
    "full",
    "engagements",
    "objectives",
    "domain",
    "changelog",
    "diff",
    "relationships",
    "decisions",
    "alerts",
    "sessions",
    "segments",
    "ooda",
    "wordlists",
    "resolved_vectors",
    "subagents",
    "artifacts",
    "goal",
  ]).annotate({
    description:
      "Type of query: summary, hosts, vulns, creds, scope, phase, flags, tasks, host, full, engagements, objectives, domain, changelog, diff, relationships, decisions, alerts, sessions (live shells/tunnels), segments (network), ooda (full situation-awareness context), wordlists (used wordlists per target:port), resolved_vectors (settled attack vectors — check before opening a vector; filter by status attempted|confirmed|resolved|blocked or a target substring), subagents (REAL running/finished subagent processes for this session — the source of truth, unlike task_graph status), artifacts (reusable weapons/loot/scripts recorded this engagement — INVOKE a recorded exploit instead of re-deriving its payload), goal (current engagement goal)",
  }),
  filter: Schema.optional(Schema.String).annotate({
    description: "Filter: IP for host query, severity for vulns, engagement name for details",
  }),
})

const NO_ENGAGEMENT = "No engagement loaded. Create one with state_update (action: create_engagement) or load an existing one (action: load_engagement)."

function formatHost(ip: string, host: EngagementSchema.Host): string {
  const lines: string[] = []
  lines.push(`[${ip}]${host.hostname ? ` (${host.hostname})` : ""}${host.os ? ` OS: ${host.os}` : ""}`)
  if (host.services.length > 0) {
    for (const svc of host.services) {
      const ver = svc.version ? ` ${svc.version}` : ""
      lines.push(`  ${svc.port}/${svc.protocol ?? "tcp"} ${svc.state ?? "open"} ${svc.service ?? ""}${ver}${svc.banner ? ` -- ${svc.banner}` : ""}`)
    }
  }
  if (host.vulns.length > 0) {
    lines.push(`  Vulns (${host.vulns.length}):`)
    for (const v of host.vulns) {
      lines.push(`    [${(v.severity ?? "medium").toUpperCase()}] ${v.title} (${v.status ?? "suspected"})${v.confidence !== undefined ? ` conf:${v.confidence}` : ""}${v.service_port ? ` port:${v.service_port}` : ""}`)
    }
  }
  if (host.access.length > 0) {
    lines.push(`  Access:`)
    for (const a of host.access) {
      lines.push(`    ${a.access_type} as ${a.username} (${a.level ?? "user"})${a.details ? ` -- ${a.details}` : ""}`)
    }
  }
  if (host.notes.length > 0) {
    lines.push(`  Notes: ${host.notes.join("; ")}`)
  }
  return lines.join("\n")
}

export const StateQueryTool = Tool.define(
  "state_query",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const background = yield* BackgroundJob.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          // Live subagent processes for THIS session -- session-scoped, not
          // engagement-scoped, so handle before the loaded-state guard. Sourced
          // from the real background-job registry, not the self-reported task graph.
          if (params.query_type === "subagents") {
            const jobs = (yield* background.list()).filter(
              (j) => j.type === "task" && j.metadata?.parentSessionId === ctx.sessionID,
            )
            if (jobs.length === 0) {
              return {
                title: "Subagents",
                metadata: { count: 0 },
                output:
                  "No subagents running or recently finished this session. (task_graph 'dispatched' status does NOT mean a subagent is running — you must launch one with the task tool.)",
              }
            }
            const running = jobs.filter((j) => j.status === "running")
            const finished = jobs.filter((j) => j.status !== "running")
            const render = (j: BackgroundJob.Info) => {
              const sid = typeof j.metadata?.sessionId === "string" ? j.metadata.sessionId : j.id
              return `  - [${j.status}] ${j.title ?? "task"} (session ${sid})${j.error ? ` -- ${j.error}` : ""}`
            }
            const out: string[] = []
            if (running.length > 0) out.push(`RUNNING (${running.length}):`, ...running.map(render))
            if (finished.length > 0) out.push(`FINISHED (${finished.length}):`, ...finished.map(render))
            return {
              title: `Subagents: ${running.length} running, ${finished.length} finished`,
              metadata: { running: running.length, finished: finished.length },
              output: out.join("\n"),
            }
          }

          // Handle engagements query separately -- doesn't require loaded state
          if (params.query_type === "engagements") {
            const engagements = yield* store.listEngagements()
            const current = yield* store.get()
            if (engagements.length === 0) {
              return {
                title: "Engagements",
                metadata: {},
                output: "No engagements found. Create one with state_update (action: create_engagement).",
              }
            }
            const lines = engagements.map((name) => {
              const marker = current && current.name === name ? " <-- LOADED" : ""
              return `  - ${name}${marker}`
            })
            return {
              title: "Engagements",
              metadata: { count: engagements.length },
              output: `Engagements (${engagements.length}):\n${lines.join("\n")}`,
            }
          }

          const state = yield* store.get()
          if (!state) {
            return { title: params.query_type, metadata: {}, output: NO_ENGAGEMENT }
          }

          switch (params.query_type) {
            case "summary": {
              const s = EngagementSchema.summary(state)
              const lines = [
                `Engagement: ${state.name} (${state.id})`,
                `Phase: ${s.current_phase} | Mode: ${s.mode}`,
                `Hosts: ${s.hosts_discovered} discovered, ${s.hosts_compromised} compromised`,
                `Vulnerabilities: ${s.vulnerabilities}`,
                `Credentials: ${s.credentials}`,
                `Flags: ${s.flags}`,
                `Attack steps: ${s.attack_steps}`,
                `Unchecked services: ${s.unchecked_services}`,
                `Scope: ${state.scope.targets.length} targets, ${state.scope.excludes.length} excludes`,
                `Objectives: ${s.objectives_completed}/${s.objectives_total} completed`,
              ]
              return { title: "Summary", metadata: s, output: lines.join("\n") }
            }

            case "hosts": {
              const hosts = Object.entries(state.hosts)
              if (hosts.length === 0) {
                return { title: "Hosts", metadata: { count: 0 }, output: "No hosts discovered yet." }
              }
              const output = hosts.map(([ip, host]) => formatHost(ip, host)).join("\n\n")
              return { title: "Hosts", metadata: { count: hosts.length }, output: `Hosts (${hosts.length}):\n\n${output}` }
            }

            case "vulns": {
              const allVulns: { ip: string; vuln: EngagementSchema.Vulnerability }[] = []
              for (const [ip, host] of Object.entries(state.hosts)) {
                for (const vuln of host.vulns) {
                  allVulns.push({ ip, vuln })
                }
              }
              if (allVulns.length === 0) {
                return { title: "Vulnerabilities", metadata: { count: 0 }, output: "No vulnerabilities recorded yet." }
              }
              const filtered = params.filter
                ? allVulns.filter((v) => v.vuln.severity === params.filter)
                : allVulns
              // Sort by severity
              const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
              filtered.sort((a, b) => (order[a.vuln.severity ?? "medium"] ?? 5) - (order[b.vuln.severity ?? "medium"] ?? 5))
              const lines = filtered.map((v) => {
                const sev = v.vuln.severity ?? "medium"
                const port = v.vuln.service_port ? `:${v.vuln.service_port}` : ""
                const conf = v.vuln.confidence !== undefined ? ` conf:${v.vuln.confidence}` : ""
                const refs = (v.vuln.references ?? []).length > 0 ? ` refs:[${(v.vuln.references ?? []).join(",")}]` : ""
                return `[${sev.toUpperCase()}] ${v.ip}${port} -- ${v.vuln.title} (${v.vuln.status ?? "suspected"})${conf}${refs}${v.vuln.description ? `\n  ${v.vuln.description}` : ""}`
              })
              const label = params.filter ? `Vulnerabilities [${params.filter}]` : "Vulnerabilities"
              return {
                title: label,
                metadata: { count: filtered.length, total: allVulns.length },
                output: `${label} (${filtered.length}${params.filter ? ` of ${allVulns.length} total` : ""}):\n\n${lines.join("\n")}`,
              }
            }

            case "creds": {
              const creds = Object.values(state.credentials)
              if (creds.length === 0) {
                return { title: "Credentials", metadata: { count: 0 }, output: "No credentials captured yet." }
              }
              const lines = creds.map((c) => {
                const vf = c.valid_for ?? []
                const validFor = vf.length > 0 ? ` valid_for:[${vf.join(",")}]` : ""
                const conf = c.confidence !== undefined ? ` conf:${c.confidence}` : ""
                return `  [${c.id}] ${c.username ?? ""} (${c.cred_type ?? "password"}) source:${c.source || "unknown"}${conf}${validFor}`
              })
              return {
                title: "Credentials",
                metadata: { count: creds.length },
                output: `Credentials (${creds.length}):\n${lines.join("\n")}`,
              }
            }

            case "scope": {
              const lines = [
                `Targets (${state.scope.targets.length}):`,
                ...(state.scope.targets.length > 0 ? state.scope.targets.map((t) => `  - ${t}`) : ["  (none)"]),
                `Excludes (${state.scope.excludes.length}):`,
                ...(state.scope.excludes.length > 0 ? state.scope.excludes.map((e) => `  - ${e}`) : ["  (none)"]),
                ...(state.scope.notes ? [`Notes: ${state.scope.notes}`] : []),
              ]
              return { title: "Scope", metadata: {}, output: lines.join("\n") }
            }

            case "phase": {
              return {
                title: "Phase",
                metadata: { phase: state.current_phase, mode: state.mode },
                output: `Current phase: ${state.current_phase}\nMode: ${state.mode}`,
              }
            }

            case "flags": {
              if (state.flags.length === 0) {
                return { title: "Flags", metadata: { count: 0 }, output: "No flags captured yet." }
              }
              const lines = state.flags.map((f, i) => `  ${i + 1}. ${f}`)
              return {
                title: "Flags",
                metadata: { count: state.flags.length },
                output: `Flags (${state.flags.length}):\n${lines.join("\n")}`,
              }
            }

            case "tasks": {
              const pending = state.task_tree.filter((t) => t.status === "pending" || t.status === "in_progress")
              if (pending.length === 0) {
                return {
                  title: "Tasks",
                  metadata: { count: 0, total: state.task_tree.length },
                  output: state.task_tree.length === 0
                    ? "No tasks in the task tree."
                    : `All ${state.task_tree.length} tasks are done or abandoned.`,
                }
              }
              const lines = pending.map((t) => {
                const diff = (t.difficulty ?? 0) > 0 ? ` difficulty:${t.difficulty}` : ""
                return `  [${(t.status ?? "pending").toUpperCase()}] ${t.id}: ${t.description}${t.target ? ` target:${t.target}` : ""}${t.technique ? ` technique:${t.technique}` : ""}${diff}`
              })
              return {
                title: "Tasks",
                metadata: { count: pending.length, total: state.task_tree.length },
                output: `Active tasks (${pending.length} of ${state.task_tree.length}):\n${lines.join("\n")}`,
              }
            }

            case "host": {
              if (!params.filter) {
                return { title: "Host", metadata: {}, output: "Error: filter parameter required (set to the host IP address)." }
              }
              const host = state.hosts[params.filter]
              if (!host) {
                const available = Object.keys(state.hosts)
                return {
                  title: "Host",
                  metadata: {},
                  output: `Host ${params.filter} not found.${available.length > 0 ? ` Known hosts: ${available.join(", ")}` : ""}`,
                }
              }
              return { title: `Host ${params.filter}`, metadata: {}, output: formatHost(params.filter, host) }
            }

            case "objectives": {
              const objectives = state.objectives ? Object.values(state.objectives) : []
              if (objectives.length === 0) {
                return { title: "Objectives", metadata: { count: 0 }, output: "No objectives defined. Add with state_update (action: add_objective)." }
              }
              let filtered = objectives
              if (params.filter) {
                filtered = objectives.filter((o) =>
                  o.status === params.filter ||
                  o.priority === params.filter ||
                  o.category === params.filter ||
                  o.id === params.filter,
                )
              }
              const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
              const statusOrder: Record<string, number> = { in_progress: 0, not_started: 1, blocked: 2, completed: 3, abandoned: 4 }
              filtered.sort((a, b) => {
                const pa = priorityOrder[a.priority ?? "medium"] ?? 2
                const pb = priorityOrder[b.priority ?? "medium"] ?? 2
                if (pa !== pb) return pa - pb
                return (statusOrder[a.status] ?? 5) - (statusOrder[b.status] ?? 5)
              })
              const lines = filtered.map((o) => {
                const parts = [`  [${o.status.toUpperCase()}] ${o.id}: ${o.title}`]
                if (o.priority) parts.push(`    priority: ${o.priority}`)
                if (o.target_hosts && o.target_hosts.length > 0) parts.push(`    targets: ${o.target_hosts.join(", ")}`)
                if (o.flags && o.flags.length > 0) parts.push(`    flags: ${o.flags.join(", ")}`)
                if (o.evidence) parts.push(`    evidence: ${o.evidence}`)
                return parts.join("\n")
              })
              const completed = objectives.filter((o) => o.status === "completed").length
              const label = params.filter ? `Objectives [${params.filter}]` : "Objectives"
              return {
                title: label,
                metadata: { count: filtered.length, total: objectives.length, completed },
                output: `${label} (${completed}/${objectives.length} completed):\n\n${lines.join("\n\n")}`,
              }
            }

            case "domain": {
              if (!state.domain) {
                return { title: "Domain", metadata: {}, output: "No domain info recorded. Use state_update set_domain to add Active Directory information." }
              }
              const dom = state.domain
              const lines = [
                `Domain: ${dom.domain_name}`,
                ...(dom.forest ? [`Forest: ${dom.forest}`] : []),
                ...(dom.domain_sid ? [`SID: ${dom.domain_sid}`] : []),
                ...(dom.domain_controllers?.length ? [`Domain Controllers: ${dom.domain_controllers.join(", ")}`] : []),
                ...(dom.domain_admins?.length ? [`Domain Admins: ${dom.domain_admins.join(", ")}`] : []),
                ...(dom.gpo_names?.length ? [`GPOs: ${dom.gpo_names.join(", ")}`] : []),
              ]
              if (dom.trusts?.length) {
                lines.push("Trusts:")
                for (const t of dom.trusts) {
                  lines.push(`  ${t.target_domain}${t.trust_type ? ` (${t.trust_type})` : ""}${t.trust_direction ? ` dir:${t.trust_direction}` : ""}${t.is_transitive ? " transitive" : ""}`)
                }
              }
              if (dom.password_policy) {
                const pp = dom.password_policy
                const parts: string[] = []
                if (pp.min_length !== undefined) parts.push(`min_length:${pp.min_length}`)
                if (pp.lockout_threshold !== undefined) parts.push(`lockout:${pp.lockout_threshold}`)
                if (pp.complexity_enabled !== undefined) parts.push(`complexity:${pp.complexity_enabled}`)
                if (parts.length > 0) lines.push(`Password Policy: ${parts.join(", ")}`)
              }
              return { title: "Domain", metadata: { domain: dom.domain_name }, output: lines.join("\n") }
            }

            case "changelog": {
              const limit = params.filter ? parseInt(params.filter, 10) || 50 : 50
              const entries = yield* store.getChangelog(undefined, limit)
              if (entries.length === 0) {
                return { title: "Changelog", metadata: { count: 0 }, output: "No changelog entries yet." }
              }
              const lines = entries.map((e) => `  [${e.timestamp}] ${e.action} ${e.entity_type}${e.entity_id ? ` (${e.entity_id})` : ""}: ${e.summary}`)
              return {
                title: "Changelog",
                metadata: { count: entries.length },
                output: `Changelog (last ${entries.length}):\n${lines.join("\n")}`,
              }
            }

            case "diff": {
              const lastTs = yield* store.getLastInjectedTimestamp()
              if (!lastTs) {
                return { title: "Diff", metadata: { count: 0 }, output: "No previous injection point. All changes are new." }
              }
              const entries = yield* store.getChangelogSince(lastTs)
              if (entries.length === 0) {
                return { title: "Diff", metadata: { count: 0, since: lastTs }, output: `No changes since last prompt injection (${lastTs}).` }
              }
              const diff = EngagementSchema.toDiffContext(entries)
              return {
                title: "Diff",
                metadata: { count: entries.length, since: lastTs },
                output: diff ?? "No changes.",
              }
            }

            case "relationships": {
              const rels = state.relationships ?? []
              if (rels.length === 0) {
                return { title: "Relationships", metadata: { count: 0 }, output: "No entity relationships recorded yet." }
              }
              let filtered = rels
              if (params.filter) {
                const f = params.filter.toUpperCase()
                filtered = rels.filter((r) =>
                  r.rel_type === f || r.source_id === params.filter || r.target_id === params.filter,
                )
              }
              const lines = filtered.map((r) =>
                `  ${r.source_type}:${r.source_id} --[${r.rel_type}]--> ${r.target_type}:${r.target_id}${r.metadata ? ` (${r.metadata})` : ""}`,
              )
              const label = params.filter ? `Relationships [${params.filter}]` : "Relationships"
              return {
                title: label,
                metadata: { count: filtered.length, total: rels.length },
                output: `${label} (${filtered.length}):\n${lines.join("\n")}`,
              }
            }

            case "resolved_vectors": {
              const vectors = state.resolved_vectors ?? []
              if (vectors.length === 0) {
                return { title: "Resolved vectors", metadata: { count: 0 }, output: "No vectors settled yet. Record dead ends / confirmed vectors with state_update (action: record_vector) so no agent re-tests them." }
              }
              // filter can be a status (attempted|confirmed|resolved|blocked) or a target substring
              const f = params.filter
              const statuses = new Set(["attempted", "confirmed", "resolved", "blocked"])
              let filtered = vectors
              if (f) {
                filtered = statuses.has(f.toLowerCase())
                  ? vectors.filter((v) => v.status === f.toLowerCase())
                  : vectors.filter((v) => v.target.includes(f) || v.vector.includes(f))
              }
              const lines = filtered.map((v) => {
                const n = v.attempts && v.attempts > 1 ? ` x${v.attempts}` : ""
                const by = v.tested_by ? ` by:${v.tested_by}` : ""
                const why = v.status === "blocked" && v.revisit_when ? ` (revisit: ${v.revisit_when})` : v.evidence ? ` — ${v.evidence}` : ""
                const head = `  [${v.status.toUpperCase()}] ${v.target} :: ${v.vector}${n}${by}${why}`
                const log = (v.attempt_log ?? [])
                  .map((a) => {
                    const icon = a.outcome === "success" ? "✓" : a.outcome === "partial" ? "~" : "✗"
                    return `      ${icon} ${a.technique}${a.detail ? ` — ${a.detail}` : ""}`
                  })
                  .join("\n")
                return log ? `${head}\n${log}` : head
              })
              const label = f ? `Resolved vectors [${f}]` : "Resolved vectors"
              return {
                title: label,
                metadata: { count: filtered.length, total: vectors.length },
                output: `${label} (${filtered.length}/${vectors.length}):\n${lines.join("\n")}`,
              }
            }

            case "decisions": {
              const limit = params.filter ? parseInt(params.filter, 10) || 20 : 20
              const decisions = yield* store.getDecisions(limit)
              if (decisions.length === 0) {
                return { title: "Decisions", metadata: { count: 0 }, output: "No decisions recorded yet. Record strategic decisions with state_update (action: add_decision)." }
              }
              const lines = decisions.map((dec) => {
                const out = dec.outcome ? ` → ${dec.outcome}` : ""
                return `  [${dec.phase}] ${dec.id}: ${dec.decision}${out}\n    Reasoning: ${dec.reasoning}${dec.alternatives?.length ? `\n    Alternatives: ${dec.alternatives.join(", ")}` : ""}${dec.outcome_notes ? `\n    Notes: ${dec.outcome_notes}` : ""}`
              })
              return {
                title: "Decisions",
                metadata: { count: decisions.length },
                output: `Decisions (last ${decisions.length}):\n\n${lines.join("\n\n")}`,
              }
            }

            case "alerts": {
              const active = yield* store.getActiveAlerts()
              if (active.length === 0) {
                return { title: "Alerts", metadata: { count: 0 }, output: "No active alerts." }
              }
              const lines = active.map((a) =>
                `  [${a.severity.toUpperCase()}] ${a.id}: ${a.title}${a.host_ip ? ` host:${a.host_ip}` : ""}${a.source_agent ? ` from:${a.source_agent}` : ""}\n    ${a.details ?? "(no details)"}`,
              )
              return {
                title: "Alerts",
                metadata: { count: active.length },
                output: `Active alerts (${active.length}):\n\n${lines.join("\n\n")}`,
              }
            }

            case "artifacts": {
              const arts = state.artifacts ?? []
              if (arts.length === 0) {
                return { title: "Artifacts", metadata: { count: 0 }, output: "No artifacts recorded. Save reusable weapons/loot/scripts with state_update (action: record_artifact) so agents INVOKE them instead of re-deriving payloads." }
              }
              const f = params.filter?.toLowerCase()
              const shown = f ? arts.filter((a) => a.name.toLowerCase().includes(f) || a.type.toLowerCase().includes(f) || (a.host_ip ?? "").includes(f)) : arts
              const lines = shown.map((a) => `  [${a.type.toUpperCase()}] ${a.name} @ ${a.path}${a.host_ip ? ` (${a.host_ip})` : ""}${a.description ? `\n    ${a.description}` : ""}`)
              return { title: "Artifacts", metadata: { count: shown.length }, output: `Recorded artifacts (INVOKE these, don't re-derive):\n${lines.join("\n")}` }
            }

            case "sessions": {
              const sessions = EngagementSchema.aliveSessions(state)
              if (sessions.length === 0) {
                return { title: "Sessions", metadata: { count: 0 }, output: "No live sessions. Track shells/tunnels with state_update (action: add_live_session)." }
              }
              const lines = sessions.map((s) => {
                const port = s.port ? `:${s.port}` : ""
                const tunnel = s.local_port ? ` local:${s.local_port}→${s.remote_target ?? "?"}` : ""
                return `  [${s.session_type.toUpperCase()}] ${s.id}: ${s.host_ip}${port} as ${s.username ?? "?"}${tunnel}${s.pid ? ` pid:${s.pid}` : ""}\n    since ${s.established_at}${s.details ? ` — ${s.details}` : ""}`
              })
              return {
                title: "Sessions",
                metadata: { count: sessions.length },
                output: `Live sessions (${sessions.length}):\n\n${lines.join("\n\n")}`,
              }
            }

            case "segments": {
              const segs = state.network_segments ?? []
              if (segs.length === 0) {
                return { title: "Segments", metadata: { count: 0 }, output: "No network segments recorded. Add with state_update (action: add_network_segment)." }
              }
              const lines = segs.map((seg) => {
                const parts = [`  [${seg.id}] ${seg.cidr}`]
                if (seg.name) parts[0] += ` (${seg.name})`
                if (seg.vlan !== undefined) parts.push(`    VLAN: ${seg.vlan}`)
                if (seg.gateway) parts.push(`    Gateway: ${seg.gateway}`)
                if (seg.pivot_host) parts.push(`    Pivot host: ${seg.pivot_host}`)
                if (seg.reachable_from?.length) parts.push(`    Reachable from: ${seg.reachable_from.join(", ")}`)
                if (seg.notes) parts.push(`    Notes: ${seg.notes}`)
                return parts.join("\n")
              })
              return {
                title: "Segments",
                metadata: { count: segs.length },
                output: `Network segments (${segs.length}):\n\n${lines.join("\n\n")}`,
              }
            }

            case "ooda": {
              const ooda = EngagementSchema.toOODAContext(state, [])
              return { title: "OODA Context", metadata: {}, output: ooda }
            }

            case "wordlists": {
              let hostIp: string | undefined
              let port: number | undefined
              let toolType: string | undefined
              if (params.filter) {
                const parts = params.filter.split(":")
                hostIp = parts[0] || undefined
                if (parts[1]) port = parseInt(parts[1], 10)
                if (parts[2]) toolType = parts[2]
              }
              const usages = yield* store.getWordlistUsages({ host_ip: hostIp, port, tool_type: toolType })
              if (usages.length === 0) {
                const ctx = hostIp ? ` for ${hostIp}${port !== undefined ? `:${port}` : ""}` : ""
                return { title: "Wordlists", metadata: { count: 0 }, output: `No wordlist usage recorded${ctx}. All wordlists are available.` }
              }
              const summary = EngagementSchema.wordlistSummary(usages, hostIp, port)
              return { title: "Wordlists", metadata: { count: usages.length }, output: `Wordlists used (${usages.length}):\n${summary}` }
            }

            case "full": {
              const compact = EngagementSchema.toCompactContext(state)
              return { title: "Full Context", metadata: {}, output: compact }
            }

            case "goal": {
              if (!state.goal) {
                return { title: "Goal", metadata: {}, output: "No goal set. Use /goal <text> or state_update set_goal to set one." }
              }
              const g = state.goal
              return {
                title: "Goal",
                metadata: { status: g.status },
                output: `Goal: "${g.text}"\nStatus: ${g.status}\nSet: ${g.set_at}${g.achieved_at ? `\nAchieved: ${g.achieved_at}` : ""}${g.evidence ? `\nEvidence: ${g.evidence}` : ""}`,
              }
            }

            default: {
              return { title: "Error", metadata: {}, output: `Unknown query type: ${params.query_type}` }
            }
          }
        }).pipe(Effect.orDie),
    }
  }),
)
