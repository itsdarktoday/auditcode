import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { TaskGraph } from "@auditcode/core/engagement/task-graph"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { makeOrchestratedSpawner } from "./task"
import DESCRIPTION from "./task-graph.txt"
import * as Tool from "./tool"

const TaskInput = Schema.Struct({
  id: Schema.String.annotate({ description: "Unique task id, e.g. 't1'." }),
  description: Schema.String.annotate({ description: "What the task accomplishes." }),
  assignedAgent: Schema.optional(Schema.String).annotate({
    description: "Subagent to run it, e.g. 'scanner', 'webapp', 'enumerator'.",
  }),
  priority: Schema.optional(TaskGraph.TaskPriority),
  target: Schema.optional(Schema.String),
  technique: Schema.optional(Schema.String),
  phase: Schema.optional(Schema.String),
  dependsOn: Schema.optional(Schema.Array(Schema.String)).annotate({
    description: "Ids of tasks that must complete first.",
  }),
}).annotate({ identifier: "TaskGraphTaskInput" })

// A single, concrete object shape shared by every action. Giving the model a
// real JSON schema (rather than an opaque Unknown) both documents the nested
// `tasks` array and stops providers that stringify unconstrained params — the
// prior cause of malformed-JSON crashes. All fields are optional; each action
// reads only the ones it needs.
const Data = Schema.Struct({
  tasks: Schema.optional(Schema.Array(TaskInput)).annotate({
    description: "For 'plan': the tasks to add.",
  }),
  id: Schema.optional(Schema.String).annotate({
    description: "For dispatch/complete/fail/abandon: the task id.",
  }),
  assignedAgent: Schema.optional(Schema.String).annotate({ description: "For dispatch: overrides the assignee." }),
  sessionId: Schema.optional(Schema.String).annotate({ description: "For dispatch: subagent session id." }),
  result: Schema.optional(Schema.String).annotate({ description: "For complete/fail: a short result note." }),
}).annotate({ identifier: "TaskGraphData" })

export const Parameters = Schema.Struct({
  action: Schema.Literals([
    "plan",
    "dispatch",
    "complete",
    "fail",
    "abandon",
    "kill",
    "list_ready",
    "list_all",
    "status",
  ]).annotate({
    description: "Task graph operation to perform.",
  }),
  data: Schema.optional(Data).annotate({
    description: "Action-specific data. See tool description for the fields each action uses.",
  }),
})

const NO_ENGAGEMENT = "No engagement loaded. Use state_update create_engagement first."

function formatTask(t: TaskGraph.TaskNode): string {
  const parts = [`[${t.status.toUpperCase()}]`, t.id]
  if (t.priority) parts.push(`(${t.priority})`)
  parts.push(t.description)
  if (t.assignedAgent) parts.push(`→ ${t.assignedAgent}`)
  if (t.target) parts.push(`@ ${t.target}`)
  if (t.dependsOn.length > 0) parts.push(`deps:[${t.dependsOn.join(",")}]`)
  return parts.join(" ")
}

export const TaskGraphTool = Tool.define(
  "task_graph",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service
    const flags = yield* RuntimeFlags.Service
    const spawn = yield* makeOrchestratedSpawner()

    // AR1: fill free concurrency slots via the rolling pump (cap-limited,
    // ledger-aware, paced). The pump also auto-refills as subagents complete, so
    // this is just the initial kick + the coordinator's "launch what's ready" verb.
    const dispatchReadyWave = Effect.fn("task_graph.dispatchReadyWave")(function* (
      ctx: Tool.Context,
      prefix: string,
    ) {
      const r = yield* spawn.pump(ctx)
      const lines = [
        `${prefix} Dispatched ${r.spawnable.length} subagent(s)${
          r.spawnable.length > 0 ? `: ${r.spawnable.map((n) => `${n.id}→${n.assignedAgent}`).join(", ")}` : ""
        }.`,
      ]
      if (r.deferred.length > 0)
        lines.push(
          `${r.deferred.length} ready but over the concurrency cap — the harness auto-launches them as slots free.`,
        )
      if (r.skipped.length > 0)
        lines.push(
          `Skipped ${r.skipped.length} (already-resolved dead-end vector): ${r.skipped.map((s) => s.node.id).join(", ")}.`,
        )
      if (r.needsAgent.length > 0)
        lines.push(
          `${r.needsAgent.length} ready task(s) have no assignedAgent and were NOT dispatched: ${r.needsAgent.map((n) => n.id).join(", ")}. Re-plan them with an agent.`,
        )
      lines.push(
        "Subagents run in the background; the harness auto-dispatches dependent tasks as slots free — do NOT poll. You'll be notified as each finishes; plan again only when the DAG drains.",
      )
      return { title: `Dispatched ${r.spawnable.length}`, metadata: {}, output: lines.join("\n") } as Tool.ExecuteResult
    })

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }

          // Defensive normalization. The typed schema should deliver a plain
          // object, but tolerate a stringified blob or common shape drift
          // (tasks array sent directly as `data`, or singular `task`) instead
          // of dying under Effect.orDie.
          let d: any = params.data ?? {}
          if (typeof d === "string") {
            try {
              d = JSON.parse(d)
            } catch {
              return {
                title: "Error",
                metadata: {},
                output: "Error: `data` was a string but not valid JSON. Send `data` as a JSON object, not text.",
              }
            }
          }
          if (Array.isArray(d)) d = { tasks: d }
          if (d && typeof d === "object" && d.task && !d.tasks) {
            d = { ...d, tasks: Array.isArray(d.task) ? d.task : [d.task] }
          }
          if (!d || typeof d !== "object") d = {}

          switch (params.action) {
            case "plan": {
              const tasks = d.tasks as Array<{
                id: string
                description: string
                assignedAgent?: string
                priority?: TaskGraph.TaskPriority
                target?: string
                technique?: string
                phase?: string
                dependsOn?: string[]
              }>
              if (!tasks || !Array.isArray(tasks) || tasks.length === 0) {
                // Orchestrator (Wave-confirm): plan with no new tasks means
                // "launch the current ready wave" — how the coordinator approves
                // the next wave after seeing the previous wave's results.
                if (flags.experimentalOrchestrator) {
                  return yield* dispatchReadyWave(_ctx, "Launching ready wave.")
                }
                return {
                  title: "Error",
                  metadata: {},
                  output:
                    'Error: data.tasks must be a non-empty array. Example: {"tasks":[{"id":"t1","description":"scan host","assignedAgent":"scanner"}]}',
                }
              }
              const now = new Date().toISOString()
              // Skip malformed entries rather than failing the whole batch, so
              // one bad task doesn't lose the others.
              const skipped: string[] = []
              const newNodes: TaskGraph.TaskNode[] = tasks.flatMap((t, i) => {
                if (!t || typeof t !== "object" || typeof t.id !== "string" || typeof t.description !== "string") {
                  skipped.push(`#${i} (needs string id + description)`)
                  return []
                }
                return [
                  {
                    id: t.id,
                    description: t.description,
                    status: "planned" as const,
                    assignedAgent: t.assignedAgent,
                    priority: t.priority,
                    target: t.target,
                    technique: t.technique,
                    phase: t.phase,
                    dependsOn: Array.isArray(t.dependsOn) ? t.dependsOn : [],
                    createdAt: now,
                    updatedAt: now,
                  },
                ]
              })
              if (newNodes.length === 0) {
                return {
                  title: "Error",
                  metadata: {},
                  output: `Error: no valid tasks. Each task needs a string id and description. Skipped: ${skipped.join(", ")}`,
                }
              }
              let graph = yield* store.getTaskGraph()
              graph = TaskGraph.addTasks(graph, newNodes)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              for (const node of newNodes) {
                yield* events.publish(PentestEvent.TaskCreated, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  taskId: node.id,
                  description: node.description,
                  assignedAgent: node.assignedAgent,
                })
              }
              const ready = TaskGraph.getReady(graph)
              const skipNote = skipped.length > 0 ? ` Skipped ${skipped.length} malformed: ${skipped.join(", ")}.` : ""
              // Orchestrator: adding tasks atomically launches the ready wave —
              // collapses the old plan→task→dispatch dance into one call. The
              // coordinator still authored the plan; the harness only runs the
              // mechanics. Flag OFF → unchanged manual behavior below.
              if (flags.experimentalOrchestrator) {
                return yield* dispatchReadyWave(_ctx, `Added ${newNodes.length} tasks.${skipNote}`)
              }
              return {
                title: `Planned ${newNodes.length} tasks`,
                metadata: {},
                output: `Added ${newNodes.length} tasks. ${ready.length} ready for dispatch.${skipNote}\n${newNodes.map(formatTask).join("\n")}`,
              }
            }

            case "dispatch": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for dispatch." }
              let graph = yield* store.getTaskGraph()
              const task = graph[id]
              if (!task) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              if (task.status !== "ready" && task.status !== "planned") {
                return { title: "Error", metadata: {}, output: `Task ${id} is ${task.status}, cannot dispatch.` }
              }
              graph = TaskGraph.updateTask(graph, id, {
                status: "dispatched",
                assignedAgent: d.assignedAgent as string | undefined ?? task.assignedAgent,
                sessionId: d.sessionId as string | undefined,
              })
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Dispatched ${id}`,
                metadata: {},
                output: `Task ${id} dispatched${d.assignedAgent ? ` to ${d.assignedAgent}` : ""}.`,
              }
            }

            case "complete": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for complete." }
              let graph = yield* store.getTaskGraph()
              if (!graph[id]) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              graph = TaskGraph.completeTask(graph, id, d.result as string | undefined)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.TaskCompleted, {
                timestamp: Date.now(),
                engagementID: state.id,
                taskId: id,
                status: "completed",
                result: d.result as string | undefined,
              })
              const nowReady = TaskGraph.getReady(graph)
              return {
                title: `Completed ${id}`,
                metadata: {},
                output: `Task ${id} completed.${nowReady.length > 0 ? ` ${nowReady.length} tasks now ready: ${nowReady.map((t) => t.id).join(", ")}` : ""}`,
              }
            }

            case "fail": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for fail." }
              let graph = yield* store.getTaskGraph()
              if (!graph[id]) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              graph = TaskGraph.failTask(graph, id, d.result as string | undefined)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.TaskCompleted, {
                timestamp: Date.now(),
                engagementID: state.id,
                taskId: id,
                status: "failed",
                result: d.result as string | undefined,
              })
              const blocked = TaskGraph.getBlocked(graph)
              return {
                title: `Failed ${id}`,
                metadata: {},
                output: `Task ${id} failed.${blocked.length > 0 ? ` ${blocked.length} tasks now blocked.` : ""}`,
              }
            }

            case "abandon": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for abandon." }
              let graph = yield* store.getTaskGraph()
              if (!graph[id]) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              graph = TaskGraph.abandonTask(graph, id)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              // De-track only. If its subagent is still running, LET IT FINISH —
              // an "abandoned" (thought-redundant) agent can still succeed, and its
              // result is still reported for the coordinator to use or ignore.
              // Reclaiming tokens on a stuck agent is `kill`, a separate deliberate act.
              return {
                title: `Abandoned ${id}`,
                metadata: {},
                output: `Task ${id} abandoned (de-tracked). If its subagent is still running it will FINISH and its result will still be reported — use it if useful, ignore if truly redundant. To hard-stop a stuck/looping/wrong subagent and reclaim tokens now, use action=kill instead.`,
              }
            }

            case "kill": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for kill." }
              const graph = yield* store.getTaskGraph()
              if (!graph[id]) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              // De-track AND hard-stop the running subagent (kill its background job,
              // free its tokens). Only for agents you're sure are stuck/looping/wrong
              // — killing loses whatever they might still have produced.
              yield* store.setTaskGraph(TaskGraph.abandonTask(graph, id))
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              let killed = 0
              if (flags.experimentalOrchestrator) killed = yield* spawn.cancel(_ctx, id)
              return {
                title: `Killed ${id}`,
                metadata: { killed },
                output:
                  killed > 0
                    ? `Task ${id} hard-stopped — ${killed} subagent(s) killed, no more tokens spent on it. Siblings unaffected.`
                    : `Task ${id} marked killed, but no running subagent was found (already finished, or not orchestrator-spawned).`,
              }
            }

            case "list_ready": {
              const graph = yield* store.getTaskGraph()
              const ready = TaskGraph.getReady(graph)
              if (ready.length === 0) {
                return { title: "No ready tasks", metadata: {}, output: "No tasks ready for dispatch." }
              }
              return {
                title: `${ready.length} ready tasks`,
                metadata: {},
                output: `Ready tasks:\n${ready.map(formatTask).join("\n")}`,
              }
            }

            case "list_all": {
              const graph = yield* store.getTaskGraph()
              const all = Object.values(graph)
              if (all.length === 0) {
                return { title: "No tasks", metadata: {}, output: "Task graph is empty." }
              }
              const counts = TaskGraph.statusSummary(graph)
              const header = Object.entries(counts).map(([k, v]) => `${k}:${v}`).join(" ")
              return {
                title: `${all.length} tasks`,
                metadata: {},
                output: `Tasks (${header}):\n${all.map(formatTask).join("\n")}`,
              }
            }

            case "status": {
              const graph = yield* store.getTaskGraph()
              const all = Object.values(graph)
              if (all.length === 0) {
                return { title: "No tasks", metadata: {}, output: "Task graph is empty." }
              }
              const counts = TaskGraph.statusSummary(graph)
              const running = TaskGraph.getRunning(graph)
              const ready = TaskGraph.getReady(graph)
              const lines = [
                `Total: ${all.length} tasks`,
                Object.entries(counts).map(([k, v]) => `  ${k}: ${v}`).join("\n"),
              ]
              if (running.length > 0) {
                lines.push(`\nActive: ${running.map((t) => `${t.id}→${t.assignedAgent ?? "?"}`).join(", ")}`)
              }
              if (ready.length > 0) {
                lines.push(`Ready to dispatch: ${ready.map((t) => t.id).join(", ")}`)
              }
              return {
                title: `Task status`,
                metadata: {},
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
