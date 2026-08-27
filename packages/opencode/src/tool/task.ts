import * as Tool from "./tool"
import DESCRIPTION from "./task.txt"
import { ToolJsonSchema } from "./json-schema"
import { SessionV1 } from "@auditcode/core/v1/session"
import { BackgroundJob } from "@/background/job"
import { Session } from "@/session/session"
import { SessionID, MessageID } from "../session/schema"
import { MessageV2 } from "../session/message-v2"
import { Agent } from "../agent/agent"
import { deriveSubagentSessionPermission } from "../agent/subagent-permissions"
import type { SessionPrompt } from "../session/prompt"
import { Config } from "@/config/config"
import { Effect, Exit, Ref, Schema, Scope, Semaphore } from "effect"
import { EffectBridge } from "@/effect/bridge"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { Database } from "@auditcode/core/database/database"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { TaskGraph } from "@auditcode/core/engagement/task-graph"
import { Orchestrator } from "@auditcode/core/engagement/orchestrator"

export interface TaskPromptOps {
  cancel(sessionID: SessionID): Effect.Effect<void>
  resolvePromptParts(template: string): Effect.Effect<SessionPrompt.PromptInput["parts"]>
  prompt(input: SessionPrompt.PromptInput): Effect.Effect<SessionV1.WithParts>
}

const id = "task"
const BACKGROUND_DESCRIPTION = [
  "Background mode: background=true launches the subagent asynchronously and returns immediately.",
  "Foreground is the default; use it when you need the result before continuing.",
  "Use background only for independent work that can run while you continue elsewhere.",
  "You will be notified automatically when it finishes.",
].join(" ")
// Kept to one line each: this string is the tool RESULT of every background
// spawn and is replayed in the transcript on every subsequent turn (25× in a
// real session). The full "don't poll / don't duplicate" guidance already lives
// in the tool description (sent once, cached), so repeating it per-result is
// pure transcript bloat. See redesign QW3.
const BACKGROUND_STARTED = "Task launched in background — you'll be notified on completion. Continue with non-overlapping work."
const BACKGROUND_UPDATED = "Context sent to the running background task — you'll be notified on completion."

// Injected into every fresh subagent prompt so the coordinator doesn't have to
// re-paste findings/creds/context (which bloats its output and re-plays every
// turn). The subagent shares the engagement state and pulls context itself.
// See redesign QW3.
const CONTEXT_PROTOCOL = [
  "<context-protocol>",
  "Your engagement state (hosts, confirmed vulns, credentials, already-tested vectors) is shared and visible to you. Before acting, query it with state_query. Do NOT re-test or re-report anything already confirmed in state, and do NOT expect findings/creds/tokens to be pasted into this prompt — pull them yourself. Record every new finding immediately via state_update / the parser tools.",
  "SCOPE: complete your PRIMARY deliverable and RETURN — do not open-endedly expand. When you uncover follow-on work (a new segment/host/vector, deeper exhaustion), record it via state_update and list it under `next:` for the coordinator to plan as its own task; do NOT chase it yourself. Other tasks may DEPEND on you — they stay blocked until you return, so returning promptly after your deliverable is met is part of the job.",
  "END your FINAL message with this machine-read result block so your work is filed accurately for the coordinator and later agents (this is parsed verbatim — do not rely on prose being interpreted):",
  "<agent-result>",
  "findings: confirmed facts you established — vulns/creds/access/live hosts+services; one per '|', or 'none'",
  "dead_ends: vectors you tried that did NOT work (so no one retries them); one per '|', or 'none'",
  "next: concrete recommended next steps; one per '|', or 'none'",
  "</agent-result>",
  "</context-protocol>",
].join("\n")

const BaseParameterFields = {
  description: Schema.String.annotate({ description: "A short (3-5 words) description of the task" }),
  prompt: Schema.String.annotate({ description: "The task for the agent to perform" }),
  subagent_type: Schema.String.annotate({ description: "The type of specialized agent to use for this task" }),
  task_id: Schema.optional(Schema.String).annotate({
    description:
      "This should only be set if you mean to resume a previous task (you can pass a prior task_id and the task will continue the same subagent session as before instead of creating a fresh one)",
  }),
  command: Schema.optional(Schema.String).annotate({ description: "The command that triggered this task" }),
}

const BaseParameters = Schema.Struct(BaseParameterFields)

export const Parameters = Schema.Struct({
  ...BaseParameterFields,
  background: Schema.optional(Schema.Boolean).annotate({
    description:
      "Run the agent in the background. You will be notified when it completes. DO NOT sleep, poll, or proactively check on its progress",
  }),
})

function renderOutput(input: {
  sessionID: SessionID
  state: "running" | "completed" | "error"
  summary?: string
  text: string
}) {
  const tag = input.state === "error" ? "task_error" : "task_result"
  return [
    `<task id="${input.sessionID}" state="${input.state}">`,
    ...(input.summary ? [`<summary>${input.summary}</summary>`] : []),
    `<${tag}>`,
    input.text,
    `</${tag}>`,
    "</task>",
  ].join("\n")
}

// P3b: condense a subagent's FINAL result before it is injected into the COORDINATOR
// (where it replays every subsequent turn — a top context-rot driver). Head+tail cap
// keeps the intro (what it did) and the tail (which carries the <agent-result> trailer
// + conclusion), dropping the bulky middle. The subagent's FULL output stays in its own
// session and its findings are in engagement state (state_query), so nothing is lost —
// only the coordinator's replayed copy shrinks. Independent of trailer compliance.
const COORD_RESULT_CAP = 3000
function condenseResult(text: string): string {
  if (text.length <= COORD_RESULT_CAP) return text
  const head = text.slice(0, 900)
  const tail = text.slice(-2000)
  return `${head}\n\n…[${text.length - 2900} chars truncated — full output in the subagent session; query engagement state for recorded findings]…\n\n${tail}`
}

// I-1: parse the machine-read <agent-result> trailer that CONTEXT_PROTOCOL asks
// every subagent to emit. This replaces guessing findings/failures from prose by
// substring match (which silently misfiled a real finding as a "failure"). Returns
// undefined when no trailer is present, so the legacy heuristic still runs —
// graceful degradation for non-compliant / older output.
export function parseResultTrailer(
  text: string,
): { findings: string[]; failures: string[]; next: string[] } | undefined {
  const blocks = text.match(/<agent-result>([\s\S]*?)<\/agent-result>/gi)
  if (!blocks || blocks.length === 0) return undefined
  const body = blocks[blocks.length - 1]!.replace(/<\/?agent-result>/gi, "")
  const pick = (labels: string[]): string[] => {
    for (const line of body.split("\n")) {
      const m = line.match(/^\s*([a-z_ ]+):\s*(.*)$/i)
      if (!m) continue
      const key = m[1]!.trim().toLowerCase().replace(/\s+/g, "_")
      if (!labels.includes(key)) continue
      return m[2]!
        .split("|")
        .map((s) => s.trim())
        .filter((s) => s.length > 0 && s.toLowerCase() !== "none")
        .map((s) => s.slice(0, 200))
        .slice(0, 10)
    }
    return []
  }
  return {
    findings: pick(["findings", "finding"]),
    failures: pick(["dead_ends", "dead_end", "failures", "failed", "failed_attempts"]),
    next: pick(["next", "recommended", "recommended_next", "next_steps"]),
  }
}

function buildContextSummary(
  params: { description: string; subagent_type: string },
  sessionID: string,
  outcome: "completed" | "error",
  text: string,
): EngagementSchema.AgentContextSummary {
  const findings: string[] = []
  const failures: string[] = []
  const next: string[] = []

  const parsed = parseResultTrailer(text)
  if (parsed) {
    // Trailer present — trust the subagent's own typed classification.
    findings.push(...parsed.findings)
    failures.push(...parsed.failures)
    next.push(...parsed.next)
  } else {
    // No trailer — fall back to the legacy prose heuristic.
    for (const line of text.split("\n")) {
      const lower = line.toLowerCase().trim()
      if (!lower) continue
      if (
        lower.includes("found") ||
        lower.includes("discovered") ||
        lower.includes("identified") ||
        lower.includes("confirmed")
      ) {
        findings.push(line.trim().slice(0, 200))
      } else if (
        lower.includes("failed") ||
        lower.includes("error") ||
        lower.includes("denied") ||
        lower.includes("timeout")
      ) {
        failures.push(line.trim().slice(0, 200))
      } else if (
        lower.includes("recommend") ||
        lower.includes("next") ||
        lower.includes("should") ||
        lower.includes("suggest")
      ) {
        next.push(line.trim().slice(0, 200))
      }
    }
  }

  // Guarantee some carried context even if everything came back empty.
  if (findings.length === 0 && failures.length === 0 && next.length === 0) {
    findings.push(text.slice(0, 500))
  }

  return {
    id: crypto.randomUUID().slice(0, 8),
    agent_type: params.subagent_type,
    timestamp: new Date().toISOString(),
    task_description: params.description,
    outcome,
    key_findings: findings.slice(0, 10),
    failed_attempts: failures.slice(0, 10),
    recommended_next: next.slice(0, 10),
  }
}

function formatPriorContext(contexts: EngagementSchema.AgentContextSummary[]): string {
  const lines: string[] = [`<prior-agent-context agent_type="${contexts[0]?.agent_type ?? "unknown"}">`]
  for (const ctx of contexts) {
    lines.push(`  <run time="${ctx.timestamp}" outcome="${ctx.outcome}" task="${ctx.task_description}">`)
    if (ctx.key_findings.length > 0) {
      lines.push(`    Findings: ${ctx.key_findings.join("; ")}`)
    }
    if (ctx.failed_attempts.length > 0) {
      lines.push(`    Failed: ${ctx.failed_attempts.join("; ")}`)
    }
    if (ctx.recommended_next.length > 0) {
      lines.push(`    Next: ${ctx.recommended_next.join("; ")}`)
    }
    lines.push(`  </run>`)
  }
  lines.push(`</prior-agent-context>`)
  return lines.join("\n")
}

// What OTHER specialist agents already did — so a fresh agent doesn't re-run
// enumeration a different agent type has already covered. Compact on purpose.
function formatOtherAgentsWork(contexts: EngagementSchema.AgentContextSummary[]): string {
  const lines: string[] = ["<other-agents-work>", "Work already done by OTHER agents this engagement — do NOT repeat it:"]
  for (const ctx of contexts) {
    const findings = ctx.key_findings.slice(0, 3).join("; ")
    lines.push(`  - [${ctx.agent_type}] ${ctx.task_description}${findings ? ` — found: ${findings}` : ""}`)
  }
  lines.push("Check state_query for the full picture before enumerating.")
  lines.push("</other-agents-work>")
  return lines.join("\n")
}

// Subagents ACTUALLY running right now (from the live background-job registry,
// not the self-reported task graph), so a fresh agent picks different work
// rather than colliding with a live sibling.
function formatInFlightSiblings(jobs: BackgroundJob.Info[]): string {
  const lines: string[] = ["<in-flight-agents>", "Subagents running RIGHT NOW — do NOT duplicate their work:"]
  for (const j of jobs) {
    const sid = typeof j.metadata?.sessionId === "string" ? j.metadata.sessionId : j.id
    lines.push(`  - [${j.status}] ${j.title ?? "task"} (session ${sid})`)
  }
  lines.push("</in-flight-agents>")
  return lines.join("\n")
}

function formatInterruptAlert(alert: EngagementSchema.Alert): string {
  return [
    `<interrupt-alert source="${alert.source_agent ?? "unknown"}" severity="${alert.severity}">`,
    `URGENT: ${alert.title}`,
    ...(alert.host_ip ? [`Host: ${alert.host_ip}`] : []),
    ...(alert.details ? [alert.details] : []),
    `This alert was raised by a running subagent and requires immediate attention.`,
    `</interrupt-alert>`,
  ].join("\n")
}

// A-4 stall watchdog wake. The harness DETECTS a gating task that has run too
// long with starved dependents and wakes the coordinator to DECIDE (it never
// resolves the stall itself — harness computes, coordinator decides). Modeled on
// formatInterruptAlert; injected via the same synthetic-prompt path.
function formatStalledTask(stall: Orchestrator.Stall): string {
  const idleMin = Math.floor(stall.idleMs / 60_000)
  const idle = idleMin >= 1 ? `${idleMin} min` : `${Math.floor(stall.idleMs / 1_000)}s`
  const ageMin = Math.floor(stall.ageMs / 60_000)
  const deps = stall.starvedDependents
    .map((d) => `${d.id}${d.assignedAgent ? `→${d.assignedAgent}` : ""}`)
    .join(", ")
  const id = stall.stalled.id
  const who = stall.stalled.assignedAgent ? ` (${stall.stalled.assignedAgent})` : ""
  return [
    `<stalled-task task="${id}" silent="${idle}" running="${ageMin} min">`,
    `Task "${id}"${who} has produced NO output for ${idle} (in flight ${ageMin} min). ${stall.starvedDependents.length} task(s) depend on it and cannot start: ${deps}.`,
    `Silence ≠ stuck: operational work (reverse shell, gadget build, tunnel) is legitimately slow and quiet. Weigh before acting — killing a working agent loses ALL its in-context progress:`,
    `- PREFER WAIT if it's a shell/exploit/tunnel build — check state_query first (a live_session or new access may be landing).`,
    `- task_graph complete {"data":{"id":"${id}","result":"..."}} — if its deliverable is ALREADY met (verify, e.g. the live_session is up), so dependents launch.`,
    `- task_graph plan {"tasks":[...]} — re-scope its open-ended follow-on into a NEW task so this gate closes.`,
    `- task_graph kill {"data":{"id":"${id}"}} — ONLY if truly hung/looping. Then RE-DELEGATE a fresh subagent — do NOT take the work over yourself (that's the solo-grind failure).`,
    `</stalled-task>`,
  ].join("\n")
}

// #1: operational roles legitimately run long AND silent (reverse shells, gadget
// builds, tunnels routinely take 20-40 min with no incremental state writes). Give
// them a larger stall threshold so the watchdog doesn't flag a WORKING agent as hung
// and prompt the coordinator to kill it (the field-run death-spiral). Other roles
// keep the base stallMs.
const OPERATIONAL_STALL_MULTIPLIER: Record<string, number> = {
  exploiter: 4,
  exploit_dev: 4,
  post_exploit: 4,
  infrastructure: 4,
}

// B: changelog actions that count as genuine forward motion in an attack branch.
// add_vuln is deliberately EXCLUDED — a branch can spam suspected vulns without
// ever converting to access, which would mask a real dead end.
const PROGRESS_ACTIONS = new Set(["add_access", "add_credential", "add_host", "complete_objective"])

// B: no-progress early-cut wake. The harness detects that the fleet keeps spending
// while ZERO new state markers land, and wakes the coordinator to DECIDE (cut the
// dead-end branch and pivot, or justify a real grind). Advisory — never auto-kills;
// progress-gated (state markers), NOT raw step count, so a hard-but-real grind on a
// confirmed target isn't murdered (the dev.6 cacti-root grind took ~2h).
function formatNoProgress(idleMs: number, inFlight: number): string {
  const mins = Math.floor(idleMs / 60_000)
  return [
    `<no-progress idle="${mins} min" active-agents="${inFlight}">`,
    `No NEW access, credential, host, or completed objective has landed in engagement state for ${mins} min while ${inFlight} subagent(s) keep spending. A branch that burns budget with ZERO new markers is usually a dead end (the dev.9 failure: ~80% of the run poured into a pivot that scored nothing and killed the foothold).`,
    `DECIDE now — do NOT just keep pouring agents in:`,
    `- Dead end → task_graph kill its tasks, BANK any reachable-but-unattacked host/segment (state_query hosts / reachable), and pivot the freed budget there.`,
    `- Genuinely hard-but-REAL grind on a confirmed-vulnerable target you're methodically working → say so and continue. This is advisory, not a stop.`,
    `- Out of leads → conclude this branch and consolidate findings.`,
    `</no-progress>`,
  ].join("\n")
}

// Compact objective prompt for an orchestrated node. Heavy context-carry
// (CONTEXT_PROTOCOL, prior/other-agent work) is prepended by the spawner, so
// this stays lean — objectives, not scripts.
function buildObjectivePrompt(node: TaskGraph.TaskNode): string {
  const parts = [node.description.trim()]
  if (node.target) parts.push(`Target: ${node.target}.`)
  if (node.technique) parts.push(`Technique/approach: ${node.technique}.`)
  parts.push(
    "Confirmed vulns, credentials, and already-settled vectors are in engagement state — query with state_query before acting, do NOT re-test what is resolved/confirmed, and record every finding via state_update / the parser tools.",
  )
  return parts.join(" ")
}

export interface PumpResult {
  spawnable: TaskGraph.TaskNode[]
  deferred: TaskGraph.TaskNode[]
  skipped: { node: TaskGraph.TaskNode; reason: string }[]
  needsAgent: TaskGraph.TaskNode[]
}

// AR1 deterministic orchestrator, ROLLING PIPELINE. Built once at tool
// construction (where layer requirements are satisfied) and returns a `pump`
// with R=never so a tool's execute can call it. TaskTool itself is untouched —
// the flag-off path can never regress.
//
// `pump(ctx)` fills free concurrency slots with any task whose deps are already
// satisfied (not the whole "wave"), paced by a stagger to avoid bursting the
// provider into rate limits, and serialized by a semaphore so concurrent
// completions can't over-fill. Each spawned subagent, on settle, marks its node
// done atomically and calls `pump` again to refill freed slots immediately — so
// the pipeline never stalls on a straggler. The coordinator steers at PLAN
// boundaries (it declared the DAG; it's told to plan again only when the DAG
// drains) and via interrupt alerts; it never has to hand-dispatch.
export const makeOrchestratedSpawner = Effect.fn("Orchestrator.makeSpawner")(function* () {
  const agent = yield* Agent.Service
  const background = yield* BackgroundJob.Service
  const config = yield* Config.Service
  const sessions = yield* Session.Service
  const scope = yield* Scope.Scope
  const database = yield* Database.Service
  const engagementStore = yield* EngagementStore.Service
  const flags = yield* RuntimeFlags.Service
  const cap = flags.orchestratorConcurrency ?? Orchestrator.DEFAULT_CONCURRENCY
  const staggerMs = flags.orchestratorStaggerMs ?? 800
  const pumpLock = Semaphore.makeUnsafe(1)
  // A-4 stall watchdog: an in-flight task older than stallMs WITH starved
  // dependents wakes the coordinator. stallCheckMs is the poll cadence.
  const stallMs = flags.orchestratorStallMs ?? 300_000
  const stallCheckMs = Math.max(15_000, Math.floor(stallMs / 2))
  // B: no-progress early-cut window (advisory wake when the fleet spends with no
  // new state markers). Shares the watchdog poll cadence.
  const noProgressMs = flags.orchestratorNoProgressMs ?? 25 * 60_000

  // REAL in-flight count from the background-job registry — the source of truth
  // for free slots (graph status can lag).
  const realInFlight = (ctx: Tool.Context) =>
    background
      .list()
      .pipe(
        Effect.map(
          (jobs) =>
            jobs.filter(
              (j) => j.type === id && j.status === "running" && j.metadata?.parentSessionId === ctx.sessionID,
            ).length,
        ),
      )

  // S-1: coalesce coordinator wake-ups. Each subagent completion goes onto this
  // queue instead of immediately re-driving the coordinator (which replays the
  // whole transcript). A single flusher fiber batches everything that lands in a
  // short window into ONE synthetic coordinator turn. Dispatch is untouched — the
  // rolling `pump` still refills slots on every settle. Interrupt alerts do NOT
  // go here; they inject immediately (separate, urgent path).
  const coalesceMs = flags.orchestratorCoalesceMs ?? 1500
  type Settled = { ctx: Tool.Context; variant: string | undefined; childId: string; description: string; status: "completed" | "error"; text: string }
  const pendingInjects = yield* Ref.make<Settled[]>([])
  const flushScheduled = yield* Ref.make(false)

  // A-4 stall-watchdog state. The spawner is a process singleton, so the watchdog
  // is a single fiber lazily started on the first pump; it reads the latest
  // coordinator ctx (for the wake path) from a Ref. `stallAlerted` dedups so each
  // stall episode wakes the coordinator once (re-armed when a task stops stalling).
  const watchdogStarted = yield* Ref.make(false)
  const lastCoordinatorCtx = yield* Ref.make<Tool.Context | undefined>(undefined)
  const stallAlerted = yield* Ref.make<Set<string>>(new Set())
  // B: no-progress state. lastProgressMs = high-water timestamp of the newest
  // progress marker seen (0 = uninitialized). noProgressAlerted dedups so we nudge
  // once per stale window; a new marker re-arms it.
  const lastProgressMs = yield* Ref.make(0)
  const noProgressAlerted = yield* Ref.make(false)

  const flushBatch = (batch: Settled[]) =>
    Effect.gen(function* () {
      if (batch.length === 0) return
      const ctx = batch[0]!.ctx
      const ops = ctx.extra?.promptOps as TaskPromptOps | undefined
      if (!ops) return
      const currentParent = yield* sessions.get(ctx.sessionID)
      const body = batch
        .map((r) =>
          renderOutput({
            sessionID: r.childId as SessionID,
            state: r.status,
            summary: r.status === "completed" ? `Subagent completed: ${r.description}` : `Subagent failed: ${r.description}`,
            text: condenseResult(r.text),
          }),
        )
        .join("\n\n")
      // One orchestrator note reflecting state AFTER the whole batch settled.
      const running = yield* realInFlight(ctx)
      const ws = Orchestrator.waveStatus(yield* engagementStore.getTaskGraph())
      const drained = running === 0 && ws.ready.length === 0 && ws.inFlight.length === 0
      const note = drained
        ? `\n\n[orchestrator] All planned tasks are settled and nothing is running (blocked: ${ws.blocked.length}). Give the next objectives via task_graph plan, or conclude against coverage/objectives — do NOT stop early if objectives remain.`
        : `\n\n[orchestrator] ${running} subagent(s) running; the harness auto-dispatches dependent tasks as slots free. You'll be notified as each finishes — do not poll.`
      yield* ops
        .prompt({
          sessionID: ctx.sessionID,
          agent: currentParent.agent ?? ctx.agent,
          variant: batch[0]!.variant,
          parts: [{ type: "text", synthetic: true, text: body + note }],
        })
        .pipe(Effect.ignore)
    })

  // Debounce: the first completion arms a single flush after `coalesceMs`; any
  // completions that land during the window join the same batch and inject as ONE
  // coordinator turn. `flushScheduled` is cleared BEFORE draining so a completion
  // arriving mid-drain re-arms (never lost; at worst one harmless empty flush).
  const enqueueInject = (item: Settled) =>
    Effect.gen(function* () {
      yield* Ref.update(pendingInjects, (a) => [...a, item])
      const start = yield* Ref.modify(flushScheduled, (scheduled) =>
        scheduled ? ([false, true] as const) : ([true, true] as const),
      )
      if (!start) return
      yield* Effect.gen(function* () {
        if (coalesceMs > 0) yield* Effect.sleep(`${coalesceMs} millis`)
        yield* Ref.set(flushScheduled, false)
        const batch = yield* Ref.getAndSet(pendingInjects, [])
        yield* flushBatch(batch).pipe(Effect.catchCause(() => Effect.void))
      }).pipe(Effect.forkIn(scope))
    })

  const spawnOne = (ctx: Tool.Context, node: TaskGraph.TaskNode) =>
    Effect.gen(function* () {
      const subagentType = node.assignedAgent!
      const description = node.description
      const cfg = yield* config.get()
      const ops = ctx.extra?.promptOps as TaskPromptOps | undefined
      if (!ops) return

      const next = yield* agent.get(subagentType)
      if (!next) return

      const parent = yield* sessions.get(ctx.sessionID)
      const childPermission = deriveSubagentSessionPermission({
        parentSessionPermission: parent.permission ?? [],
        subagent: next,
      })
      const childToolDenies = [
        ...(next.permission.some((rule) => rule.permission === "todowrite")
          ? []
          : [{ permission: "todowrite" as const, pattern: "*" as const, action: "deny" as const }]),
        ...(next.permission.some((rule) => rule.permission === id)
          ? []
          : [{ permission: id, pattern: "*" as const, action: "deny" as const }]),
        ...(cfg.experimental?.primary_tools?.map((permission) => ({
          permission,
          pattern: "*" as const,
          action: "deny" as const,
        })) ?? []),
      ]
      const nextSession = yield* sessions.create({
        parentID: ctx.sessionID,
        title: description + ` (@${next.name} subagent)`,
        agent: next.name,
        permission: [
          ...childPermission,
          ...childToolDenies.filter(
            (deny) =>
              !childPermission.some(
                (rule) =>
                  rule.permission === deny.permission &&
                  rule.pattern === deny.pattern &&
                  rule.action === deny.action,
              ),
          ),
        ],
      })

      const msg = yield* MessageV2.get({ sessionID: ctx.sessionID, messageID: ctx.messageID }).pipe(
        Effect.provideService(Database.Service, database),
        Effect.orDie,
      )
      if (msg.info.role !== "assistant") return
      const variant = msg.info.variant
      const model = next.model ?? { modelID: msg.info.modelID, providerID: msg.info.providerID }
      const metadata = {
        parentSessionId: ctx.sessionID,
        sessionId: nextSession.id,
        model,
        background: true,
        taskNodeId: node.id,
      }

      const priorContexts = yield* engagementStore.getAgentContexts(subagentType, 5)
      const recentContexts = yield* engagementStore.getRecentAgentContexts(10)
      const otherAgents = recentContexts.filter((c) => c.agent_type !== subagentType).slice(0, 6)
      const siblings = (yield* background.list()).filter(
        (j) =>
          j.type === id &&
          j.status === "running" &&
          j.metadata?.parentSessionId === ctx.sessionID &&
          j.metadata?.sessionId !== nextSession.id,
      )
      const blocks: string[] = [CONTEXT_PROTOCOL]
      if (priorContexts.length > 0) blocks.push(formatPriorContext(priorContexts))
      if (otherAgents.length > 0) blocks.push(formatOtherAgentsWork(otherAgents))
      if (siblings.length > 0) blocks.push(formatInFlightSiblings(siblings))
      const augmentedPrompt = blocks.join("\n\n") + "\n\n" + buildObjectivePrompt(node)

      const runTask = Effect.fn("Orchestrator.runTask")(function* () {
        const parts = yield* ops.resolvePromptParts(augmentedPrompt)
        const result = yield* ops.prompt({
          messageID: MessageID.ascending(),
          sessionID: nextSession.id,
          model: { modelID: model.modelID, providerID: model.providerID },
          variant: next.model ? undefined : variant,
          agent: next.name,
          parts,
        })
        return result.parts.findLast((item) => item.type === "text")?.text ?? ""
      })

      const inject = Effect.fn("Orchestrator.inject")(function* (
        state: "running" | "completed" | "error",
        text: string,
      ) {
        const currentParent = yield* sessions.get(ctx.sessionID)
        yield* ops
          .prompt({
            sessionID: ctx.sessionID,
            agent: currentParent.agent ?? ctx.agent,
            variant,
            parts: [
              {
                type: "text",
                synthetic: true,
                text: renderOutput({
                  sessionID: nextSession.id,
                  state,
                  summary:
                    state === "completed"
                      ? `Subagent completed: ${description}`
                      : state === "error"
                        ? `Subagent failed: ${description}`
                        : `Interrupt alert for: ${description}`,
                  text,
                }),
              },
            ],
          })
          .pipe(Effect.ignore, Effect.forkIn(scope, { startImmediately: true }))
      })

      // On settle: atomically mark the node done, refill freed slots (rolling —
      // no straggler wait), then inject the result. When the whole DAG has
      // drained, nudge the coordinator for the next plan (completion is its call).
      const onSettle = Effect.fn("Orchestrator.onSettle")(function* (status: "completed" | "error", text: string) {
        yield* engagementStore.modifyTaskGraph((g) =>
          status === "completed"
            ? TaskGraph.completeTask(g, node.id, text.slice(0, 200))
            : TaskGraph.failTask(g, node.id, text.slice(0, 200)),
        )
        const saved = yield* engagementStore.get()
        if (saved) yield* engagementStore.save(saved)
        yield* engagementStore.addAgentContext(
          buildContextSummary({ description, subagent_type: subagentType }, nextSession.id, status, text),
        )

        // Rolling refill: dependents whose deps just cleared start now. This is
        // what keeps the pipeline moving — it does NOT depend on the coordinator
        // being woken, so coalescing the wake-up (below) never stalls dispatch.
        yield* pump(ctx)

        // S-1: enqueue for a coalesced coordinator wake-up instead of re-driving a
        // full coordinator turn per completion. The running/drained note is built
        // at flush time so it reflects state after the whole batch.
        yield* enqueueInject({ ctx, variant, childId: nextSession.id, description, status, text })
      })

      const notify = Effect.fn("Orchestrator.notify")(function* (jobID: string) {
        yield* background.wait({ id: jobID }).pipe(
          Effect.flatMap((result) =>
            Effect.gen(function* () {
              if (result.info?.status === "completed") yield* onSettle("completed", result.info.output ?? "")
              else if (result.info?.status === "error") yield* onSettle("error", result.info.error ?? "")
            }),
          ),
          Effect.forkIn(scope, { startImmediately: true }),
        )
      })

      const info = yield* background.start({
        id: nextSession.id,
        type: id,
        title: description,
        metadata,
        onPromote: notify(nextSession.id),
        run: runTask().pipe(Effect.onInterrupt(() => ops.cancel(nextSession.id))),
      })
      yield* notify(info.id)

      yield* Effect.gen(function* () {
        while (true) {
          yield* Effect.sleep("2 seconds")
          const alerts = yield* engagementStore.drainInterruptAlerts()
          for (const alert of alerts) yield* inject("running", formatInterruptAlert(alert))
        }
      }).pipe(Effect.interruptible, Effect.forkIn(scope, { startImmediately: true }))
    })

  // A-4 stall watchdog. Every stallCheckMs, wake the coordinator ONCE per stall
  // episode for any in-flight task that has run > stallMs while dependents starve.
  // It only DETECTS + WAKES; the coordinator decides (kill/complete/re-plan). A
  // wake failure must never kill the fiber, so injects are swallowed.
  const watchdogLoop = Effect.gen(function* () {
    while (true) {
      yield* Effect.sleep(`${stallCheckMs} millis`)
      const ctx = yield* Ref.get(lastCoordinatorCtx)
      if (!ctx) continue
      const ops = ctx.extra?.promptOps as TaskPromptOps | undefined
      if (!ops) continue
      const graph = yield* engagementStore.getTaskGraph()
      // #1: build the per-task last-activity map so detectStall gates on SILENCE, not
      // dispatch-age — a subagent still emitting tool-calls is working, not hung. Map
      // node→child-session via job metadata, then MAX(part.time_created) per session.
      const jobs = yield* background.list()
      const nodeToSession: Record<string, SessionID> = {}
      for (const j of jobs) {
        if (j.type !== id || j.status !== "running" || j.metadata?.parentSessionId !== ctx.sessionID) continue
        const nodeId = j.metadata?.taskNodeId as string | undefined
        const sid = j.metadata?.sessionId as string | undefined
        if (nodeId && sid) nodeToSession[nodeId] = sid as SessionID
      }
      const activityBySession = yield* MessageV2.lastActivityBySession(Object.values(nodeToSession)).pipe(
        Effect.provideService(Database.Service, database),
      )
      const lastActivityMs: Record<string, number> = {}
      for (const [nodeId, sid] of Object.entries(nodeToSession)) {
        const ms = activityBySession[sid]
        if (ms !== undefined) lastActivityMs[nodeId] = ms
      }
      const stalls = Orchestrator.detectStall(graph, {
        stallMs,
        nowMs: Date.now(),
        lastActivityMs,
        roleStallMultiplier: OPERATIONAL_STALL_MULTIPLIER,
      })
      // Re-arm: drop alerts for tasks that are no longer stalled so a genuine
      // re-stall alerts once more; keep only still-stalled ids.
      const stalledIds = new Set(stalls.map((s) => s.stalled.id))
      yield* Ref.update(stallAlerted, (set) => new Set([...set].filter((id) => stalledIds.has(id))))
      const alerted = yield* Ref.get(stallAlerted)
      for (const stall of stalls) {
        if (alerted.has(stall.stalled.id)) continue
        yield* Ref.update(stallAlerted, (set) => new Set(set).add(stall.stalled.id))
        const currentParent = yield* sessions.get(ctx.sessionID)
        yield* ops
          .prompt({
            sessionID: ctx.sessionID,
            agent: currentParent.agent ?? ctx.agent,
            variant: undefined,
            parts: [{ type: "text", synthetic: true, text: formatStalledTask(stall) }],
          })
          .pipe(Effect.ignore)
      }

      // B: no-progress early-cut advisory. Newest progress marker vs now; fire ONCE
      // per stale window when the fleet is actively spending; re-arm on a new marker.
      const nowMs = Date.now()
      const changelog = yield* engagementStore.getChangelog()
      let newestProgress = 0
      for (const entry of changelog) {
        if (!PROGRESS_ACTIONS.has(entry.action)) continue
        const t = Date.parse(entry.timestamp)
        if (!Number.isNaN(t) && t > newestProgress) newestProgress = t
      }
      const prevProgress = yield* Ref.get(lastProgressMs)
      if (prevProgress === 0) {
        // First observation: start the no-progress clock now (full grace window).
        yield* Ref.set(lastProgressMs, Math.max(newestProgress, nowMs))
      } else if (newestProgress > prevProgress) {
        // A new marker landed → forward motion; re-arm.
        yield* Ref.set(lastProgressMs, newestProgress)
        yield* Ref.set(noProgressAlerted, false)
      } else {
        const already = yield* Ref.get(noProgressAlerted)
        const active = yield* realInFlight(ctx)
        if (!already && active > 0 && nowMs - prevProgress >= noProgressMs) {
          yield* Ref.set(noProgressAlerted, true)
          const currentParent = yield* sessions.get(ctx.sessionID)
          yield* ops
            .prompt({
              sessionID: ctx.sessionID,
              agent: currentParent.agent ?? ctx.agent,
              variant: undefined,
              parts: [{ type: "text", synthetic: true, text: formatNoProgress(nowMs - prevProgress, active) }],
            })
            .pipe(Effect.ignore)
        }
      }
    }
  }).pipe(Effect.catchCause(() => Effect.void))

  // Record the latest coordinator ctx (for the wake path) and lazily start the
  // single watchdog fiber on the first pump. Orchestrator-gated.
  const startWatchdog = (ctx: Tool.Context) =>
    Effect.gen(function* () {
      yield* Ref.set(lastCoordinatorCtx, ctx)
      if (!flags.experimentalOrchestrator) return
      const already = yield* Ref.getAndSet(watchdogStarted, true)
      if (already) return
      yield* watchdogLoop.pipe(Effect.interruptible, Effect.forkIn(scope, { startImmediately: true }))
    })

  // Fill free slots with ready tasks (deps satisfied), paced + serialized.
  const pump = (ctx: Tool.Context): Effect.Effect<PumpResult> =>
    pumpLock.withPermits(1)(
      Effect.gen(function* () {
        yield* startWatchdog(ctx)
        const cur = yield* engagementStore.get()
        const resolvedVectors = cur?.resolved_vectors ?? []
        const graph = yield* engagementStore.getTaskGraph()
        const inFlight = yield* realInFlight(ctx)
        const sel = Orchestrator.selectWave(graph, { concurrency: cap, inFlight, resolvedVectors })
        const spawnable = sel.spawn.filter((n) => !!n.assignedAgent)
        const needsAgent = sel.spawn.filter((n) => !n.assignedAgent)

        if (sel.skipped.length > 0 || spawnable.length > 0) {
          yield* engagementStore.modifyTaskGraph((g) => {
            let x = g
            for (const s of sel.skipped) x = TaskGraph.abandonTask(x, s.node.id)
            for (const n of spawnable) {
              x = TaskGraph.updateTask(x, n.id, { status: "dispatched", assignedAgent: n.assignedAgent })
            }
            return x
          })
          const saved = yield* engagementStore.get()
          if (saved) yield* engagementStore.save(saved)
        }

        for (const [i, n] of spawnable.entries()) {
          if (i > 0 && staggerMs > 0) yield* Effect.sleep(`${staggerMs} millis`)
          yield* spawnOne(ctx, n)
        }
        return { spawnable, deferred: sel.deferred, skipped: sel.skipped, needsAgent }
      }),
    ).pipe(Effect.orDie)

  // Hard-stop the running subagent(s) for a task node. Each orchestrated job is
  // tagged with metadata.taskNodeId, so we find its live background job and
  // cancel BOTH the session prompt (ops.cancel) and the background fiber
  // (background.cancel) — the same combo TaskTool uses on abort. Independent per
  // job, so cancelling one never touches sibling subagents. Returns how many
  // were stopped.
  const cancel = (ctx: Tool.Context, nodeId: string) =>
    Effect.gen(function* () {
      const ops = ctx.extra?.promptOps as TaskPromptOps | undefined
      const jobs = (yield* background.list()).filter(
        (j) =>
          j.type === id &&
          j.status === "running" &&
          j.metadata?.parentSessionId === ctx.sessionID &&
          j.metadata?.taskNodeId === nodeId,
      )
      for (const j of jobs) {
        if (ops) yield* ops.cancel(SessionID.make(j.id)).pipe(Effect.ignore)
        yield* background.cancel(j.id).pipe(Effect.ignore)
      }
      return jobs.length
    }).pipe(Effect.orDie)

  return { pump, cancel }
})

export const TaskTool = Tool.define(
  id,
  Effect.gen(function* () {
    const agent = yield* Agent.Service
    const background = yield* BackgroundJob.Service
    const config = yield* Config.Service
    const sessions = yield* Session.Service
    const scope = yield* Scope.Scope
    const flags = yield* RuntimeFlags.Service
    const database = yield* Database.Service
    const engagementStore = yield* EngagementStore.Service

    const run = Effect.fn("TaskTool.execute")(function* (
      params: Schema.Schema.Type<typeof Parameters>,
      ctx: Tool.Context,
    ) {
      const cfg = yield* config.get()
      const isPentestCoordinator = ctx.agent === "pentest" || ctx.agent === "recon"
      const runInBackground = params.background === true || (params.background !== false && isPentestCoordinator)
      if (runInBackground && !flags.experimentalBackgroundSubagents && !isPentestCoordinator) {
        return yield* Effect.fail(
          new Error("Background subagents require OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS=true"),
        )
      }

      if (!ctx.extra?.bypassAgentCheck) {
        yield* ctx.ask({
          permission: id,
          patterns: [params.subagent_type],
          always: ["*"],
          metadata: {
            description: params.description,
            subagent_type: params.subagent_type,
          },
        })
      }

      const next = yield* agent.get(params.subagent_type)
      if (!next) {
        return yield* Effect.fail(new Error(`Unknown agent type: ${params.subagent_type} is not a valid agent type`))
      }

      const session = params.task_id
        ? yield* sessions.get(SessionID.make(params.task_id)).pipe(Effect.catchCause(() => Effect.succeed(undefined)))
        : undefined
      const parent = yield* sessions.get(ctx.sessionID)
      const childPermission = deriveSubagentSessionPermission({
        parentSessionPermission: parent.permission ?? [],
        subagent: next,
      })
      const childToolDenies = [
        ...(next.permission.some((rule) => rule.permission === "todowrite")
          ? []
          : [{ permission: "todowrite" as const, pattern: "*" as const, action: "deny" as const }]),
        ...(next.permission.some((rule) => rule.permission === id)
          ? []
          : [{ permission: id, pattern: "*" as const, action: "deny" as const }]),
        ...(cfg.experimental?.primary_tools?.map((permission) => ({
          permission,
          pattern: "*" as const,
          action: "deny" as const,
        })) ?? []),
      ]
      const nextSession =
        session ??
        (yield* sessions.create({
          parentID: ctx.sessionID,
          title: params.description + ` (@${next.name} subagent)`,
          agent: next.name,
          permission: [
            ...childPermission,
            ...childToolDenies.filter(
              (deny) =>
                !childPermission.some(
                  (rule) =>
                    rule.permission === deny.permission && rule.pattern === deny.pattern && rule.action === deny.action,
                ),
            ),
          ],
        }))

      const msg = yield* MessageV2.get({ sessionID: ctx.sessionID, messageID: ctx.messageID }).pipe(
        Effect.provideService(Database.Service, database),
        Effect.orDie,
      )
      if (msg.info.role !== "assistant") return yield* Effect.fail(new Error("Not an assistant message"))
      const variant = msg.info.variant

      const model = next.model ?? {
        modelID: msg.info.modelID,
        providerID: msg.info.providerID,
      }
      const metadata = {
        parentSessionId: ctx.sessionID,
        sessionId: nextSession.id,
        model,
        ...(runInBackground ? { background: true } : {}),
      }

      yield* ctx.metadata({
        title: params.description,
        metadata,
      })

      const ops = ctx.extra?.promptOps as TaskPromptOps
      if (!ops) return yield* Effect.fail(new Error("TaskTool requires promptOps in ctx.extra"))

      // Agent Context Carry: on a fresh spawn, tell the subagent (a) what its
      // own type did before, (b) what OTHER agent types already did (cross-type
      // dedup), and (c) which sibling tasks are running right now. This is the
      // fix for subagents re-enumerating work peers already finished.
      let augmentedPrompt = params.prompt
      if (!params.task_id) {
        const priorContexts = yield* engagementStore.getAgentContexts(params.subagent_type, 5)
        const recentContexts = yield* engagementStore.getRecentAgentContexts(10)
        const otherAgents = recentContexts.filter((c) => c.agent_type !== params.subagent_type).slice(0, 6)
        const inFlight = (yield* background.list()).filter(
          (j) =>
            j.type === "task" &&
            j.status === "running" &&
            j.metadata?.parentSessionId === ctx.sessionID &&
            j.metadata?.sessionId !== nextSession.id,
        )

        const blocks: string[] = [CONTEXT_PROTOCOL]
        if (priorContexts.length > 0) blocks.push(formatPriorContext(priorContexts))
        if (otherAgents.length > 0) blocks.push(formatOtherAgentsWork(otherAgents))
        if (inFlight.length > 0) blocks.push(formatInFlightSiblings(inFlight))
        if (blocks.length > 0) augmentedPrompt = blocks.join("\n\n") + "\n\n" + params.prompt
      }

      const runTask = Effect.fn("TaskTool.runTask")(function* () {
        const parts = yield* ops.resolvePromptParts(augmentedPrompt)
        const result = yield* ops.prompt({
          messageID: MessageID.ascending(),
          sessionID: nextSession.id,
          model: {
            modelID: model.modelID,
            providerID: model.providerID,
          },
          variant: next.model ? undefined : variant,
          agent: next.name,
          parts,
        })
        return result.parts.findLast((item) => item.type === "text")?.text ?? ""
      })

      const inject = Effect.fn("TaskTool.injectBackgroundResult")(function* (
        state: "running" | "completed" | "error",
        text: string,
      ) {
        const currentParent = yield* sessions.get(ctx.sessionID)
        yield* ops
          .prompt({
            sessionID: ctx.sessionID,
            agent: currentParent.agent ?? ctx.agent,
            variant,
            parts: [
              {
                type: "text",
                synthetic: true,
                text: renderOutput({
                  sessionID: nextSession.id,
                  state,
                  summary:
                    state === "completed"
                      ? `Background task completed: ${params.description}`
                      : state === "error"
                        ? `Background task failed: ${params.description}`
                        : `Interrupt alert for: ${params.description}`,
                  text,
                }),
              },
            ],
          })
          .pipe(Effect.ignore, Effect.forkIn(scope, { startImmediately: true }))
      })

      const notify = Effect.fn("TaskTool.notifyBackgroundResult")(function* (jobID: string) {
        yield* background.wait({ id: jobID }).pipe(
          Effect.flatMap((result) =>
            Effect.gen(function* () {
              if (result.info?.status === "completed") {
                const text = result.info.output ?? ""
                const ctxSummary = buildContextSummary(params, nextSession.id, "completed", text)
                yield* engagementStore.addAgentContext(ctxSummary)
                yield* inject("completed", condenseResult(text))
              } else if (result.info?.status === "error") {
                const text = result.info.error ?? ""
                const ctxSummary = buildContextSummary(params, nextSession.id, "error", text)
                yield* engagementStore.addAgentContext(ctxSummary)
                yield* inject("error", condenseResult(text))
              }
            }),
          ),
          Effect.forkIn(scope, { startImmediately: true }),
        )
      })

      if (yield* background.extend({ id: nextSession.id, run: runTask() })) {
        return {
          title: params.description,
          metadata: {
            ...metadata,
            background: true,
            jobId: nextSession.id,
          },
          output: renderOutput({
            sessionID: nextSession.id,
            state: "running",
            summary: "Background task updated",
            text: BACKGROUND_UPDATED,
          }),
        }
      }

      const info = yield* background.start({
        id: nextSession.id,
        type: id,
        title: params.description,
        metadata,
        onPromote: Effect.all([
          ctx.metadata({
            title: params.description,
            metadata: { ...metadata, background: true, jobId: nextSession.id },
          }),
          notify(nextSession.id),
        ]),
        run: runTask().pipe(Effect.onInterrupt(() => ops.cancel(nextSession.id))),
      })

      function backgroundResult() {
        return {
          title: params.description,
          metadata: {
            ...metadata,
            background: true,
            jobId: info.id,
          },
          output: renderOutput({
            sessionID: nextSession.id,
            state: "running",
            summary: "Background task started",
            text: BACKGROUND_STARTED,
          }),
        }
      }

      if (runInBackground) {
        yield* notify(info.id)
        // Fork interrupt alert watcher for background subagent
        yield* Effect.gen(function* () {
          while (true) {
            yield* Effect.sleep("2 seconds")
            const alerts = yield* engagementStore.drainInterruptAlerts()
            for (const alert of alerts) {
              yield* inject("running", formatInterruptAlert(alert))
            }
          }
        }).pipe(Effect.interruptible, Effect.forkIn(scope, { startImmediately: true }))
        return backgroundResult()
      }

      const runCancel = yield* EffectBridge.make()
      const cancel = ops.cancel(nextSession.id)

      function onAbort() {
        runCancel.fork(cancel)
      }

      return yield* Effect.acquireUseRelease(
        Effect.sync(() => {
          ctx.abort.addEventListener("abort", onAbort)
        }),
        () =>
          Effect.gen(function* () {
            const result = yield* Effect.raceFirst(
              background.wait({ id: nextSession.id }).pipe(Effect.map((waited) => waited.info)),
              background.waitForPromotion(nextSession.id),
            )
            if (result?.metadata?.background === true) return backgroundResult()
            if (result?.status === "error") {
              const errText = result.error ?? "Task failed"
              const ctxSummary = buildContextSummary(params, nextSession.id, "error", errText)
              yield* engagementStore.addAgentContext(ctxSummary)
              return yield* Effect.fail(new Error(errText))
            }
            if (result?.status === "cancelled") return yield* Effect.fail(new Error("Task cancelled"))
            const outputText = result?.output ?? ""
            const ctxSummary = buildContextSummary(params, nextSession.id, "completed", outputText)
            yield* engagementStore.addAgentContext(ctxSummary)
            return {
              title: params.description,
              metadata,
              output: renderOutput({ sessionID: nextSession.id, state: "completed", text: condenseResult(outputText) }),
            }
          }),
        (_, exit) =>
          Effect.gen(function* () {
            if (Exit.hasInterrupts(exit))
              yield* Effect.all([cancel, background.cancel(nextSession.id)], { discard: true })
          }).pipe(
            Effect.ensuring(
              Effect.sync(() => {
                ctx.abort.removeEventListener("abort", onAbort)
              }),
            ),
          ),
      )
    })

    return {
      description: flags.experimentalBackgroundSubagents
        ? [DESCRIPTION, BACKGROUND_DESCRIPTION].join("\n\n")
        : DESCRIPTION,
      parameters: Parameters,
      jsonSchema: flags.experimentalBackgroundSubagents ? undefined : ToolJsonSchema.fromSchema(BaseParameters),
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context) =>
        run(params, ctx).pipe(Effect.orDie),
    }
  }),
)
