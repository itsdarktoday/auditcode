export * as TaskGraph from "./task-graph"

import { Schema } from "effect"

export const TaskStatus = Schema.Literals([
  "planned",
  "ready",
  "dispatched",
  "running",
  "completed",
  "failed",
  "blocked",
  "abandoned",
])
export type TaskStatus = typeof TaskStatus.Type

export const TaskPriority = Schema.Literals(["critical", "high", "medium", "low"])
export type TaskPriority = typeof TaskPriority.Type

export const TaskNode = Schema.Struct({
  id: Schema.String,
  parentId: Schema.optional(Schema.String),
  description: Schema.String,
  status: TaskStatus,
  assignedAgent: Schema.optional(Schema.String),
  priority: Schema.optional(TaskPriority),
  target: Schema.optional(Schema.String),
  technique: Schema.optional(Schema.String),
  phase: Schema.optional(Schema.String),
  dependsOn: Schema.Array(Schema.String),
  result: Schema.optional(Schema.String),
  sessionId: Schema.optional(Schema.String),
  createdAt: Schema.String,
  updatedAt: Schema.String,
}).annotate({ identifier: "TaskGraph.TaskNode" })
export type TaskNode = typeof TaskNode.Type

export type TaskNodes = Record<string, TaskNode>

export function computeReadiness(tasks: TaskNodes): TaskNodes {
  const updated = { ...tasks }
  for (const [id, task] of Object.entries(updated)) {
    if (task.status !== "planned" && task.status !== "blocked") continue
    const allDepsCompleted = task.dependsOn.every((depId) => {
      const dep = updated[depId]
      return dep?.status === "completed"
    })
    const anyDepFailed = task.dependsOn.some((depId) => {
      const dep = updated[depId]
      return dep?.status === "failed" || dep?.status === "abandoned"
    })
    if (anyDepFailed) {
      updated[id] = { ...task, status: "blocked", updatedAt: new Date().toISOString() }
    } else if (allDepsCompleted) {
      updated[id] = { ...task, status: "ready", updatedAt: new Date().toISOString() }
    }
  }
  return updated
}

export function getReady(tasks: TaskNodes): TaskNode[] {
  return Object.values(tasks).filter((t) => t.status === "ready")
}

export function getByAgent(tasks: TaskNodes, agent: string): TaskNode[] {
  return Object.values(tasks).filter((t) => t.assignedAgent === agent)
}

export function getBlocked(tasks: TaskNodes): TaskNode[] {
  return Object.values(tasks).filter((t) => t.status === "blocked")
}

export function getRunning(tasks: TaskNodes): TaskNode[] {
  return Object.values(tasks).filter((t) => t.status === "running" || t.status === "dispatched")
}

export function addTask(tasks: TaskNodes, task: TaskNode): TaskNodes {
  const updated = { ...tasks, [task.id]: task }
  return computeReadiness(updated)
}

export function addTasks(tasks: TaskNodes, newTasks: TaskNode[]): TaskNodes {
  const updated = { ...tasks }
  for (const task of newTasks) {
    updated[task.id] = task
  }
  return computeReadiness(updated)
}

export function updateTask(tasks: TaskNodes, id: string, patch: Partial<TaskNode>): TaskNodes {
  const existing = tasks[id]
  if (!existing) return tasks
  const updated = { ...tasks, [id]: { ...existing, ...patch, updatedAt: new Date().toISOString() } }
  return computeReadiness(updated)
}

export function completeTask(tasks: TaskNodes, id: string, result?: string): TaskNodes {
  return updateTask(tasks, id, { status: "completed", result })
}

export function failTask(tasks: TaskNodes, id: string, result?: string): TaskNodes {
  return updateTask(tasks, id, { status: "failed", result })
}

export function abandonTask(tasks: TaskNodes, id: string): TaskNodes {
  return updateTask(tasks, id, { status: "abandoned" })
}

export function statusSummary(tasks: TaskNodes): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const task of Object.values(tasks)) {
    counts[task.status] = (counts[task.status] ?? 0) + 1
  }
  return counts
}
