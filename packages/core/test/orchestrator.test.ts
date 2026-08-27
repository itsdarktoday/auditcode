import { describe, expect, test } from "bun:test"
import { Orchestrator } from "@auditcode/core/engagement/orchestrator"
import { TaskGraph } from "@auditcode/core/engagement/task-graph"
import type { ResolvedVector } from "@auditcode/core/engagement/schema"

function node(patch: Partial<TaskGraph.TaskNode> & { id: string }): TaskGraph.TaskNode {
  return {
    id: patch.id,
    description: patch.description ?? `task ${patch.id}`,
    status: patch.status ?? "planned",
    dependsOn: patch.dependsOn ?? [],
    createdAt: patch.createdAt ?? "2026-07-15T00:00:00.000Z",
    updatedAt: patch.updatedAt ?? "2026-07-15T00:00:00.000Z",
    assignedAgent: patch.assignedAgent,
    priority: patch.priority,
    target: patch.target,
    technique: patch.technique,
    phase: patch.phase,
    result: patch.result,
    sessionId: patch.sessionId,
    parentId: patch.parentId,
  }
}

function graph(...nodes: TaskGraph.TaskNode[]): TaskGraph.TaskNodes {
  const g: TaskGraph.TaskNodes = {}
  for (const n of nodes) g[n.id] = n
  // run readiness so planned nodes with satisfied deps become "ready"
  return TaskGraph.computeReadiness(g)
}

describe("Orchestrator.selectWave — Risk 3: over-eager dispatch", () => {
  test("never spawns more than the concurrency cap", () => {
    const g = graph(
      node({ id: "a", status: "ready" }),
      node({ id: "b", status: "ready" }),
      node({ id: "c", status: "ready" }),
      node({ id: "d", status: "ready" }),
    )
    const sel = Orchestrator.selectWave(g, { concurrency: 2 })
    expect(sel.spawn).toHaveLength(2)
    expect(sel.deferred).toHaveLength(2)
  })

  test("counts already-running nodes against the cap", () => {
    const g = graph(
      node({ id: "run1", status: "running" }),
      node({ id: "a", status: "ready" }),
      node({ id: "b", status: "ready" }),
    )
    const sel = Orchestrator.selectWave(g, { concurrency: 2 })
    // one slot left (cap 2 - 1 running)
    expect(sel.spawn).toHaveLength(1)
    expect(sel.deferred).toHaveLength(1)
  })

  test("dispatched nodes also occupy a slot", () => {
    const g = graph(
      node({ id: "disp", status: "dispatched" }),
      node({ id: "disp2", status: "dispatched" }),
      node({ id: "a", status: "ready" }),
    )
    const sel = Orchestrator.selectWave(g, { concurrency: 2 })
    expect(sel.spawn).toHaveLength(0)
    expect(sel.deferred).toHaveLength(1)
  })

  test("explicit inFlight (real liveness) overrides graph-derived count — rolling refill", () => {
    // Graph shows nothing running, but the background registry says 2 are live.
    const g = graph(
      node({ id: "a", status: "ready" }),
      node({ id: "b", status: "ready" }),
      node({ id: "c", status: "ready" }),
    )
    // cap 3, 2 really in flight -> exactly 1 free slot
    const sel = Orchestrator.selectWave(g, { concurrency: 3, inFlight: 2 })
    expect(sel.spawn).toHaveLength(1)
    expect(sel.deferred).toHaveLength(2)
  })

  test("no free slots when real in-flight already at cap", () => {
    const g = graph(node({ id: "a", status: "ready" }), node({ id: "b", status: "ready" }))
    const sel = Orchestrator.selectWave(g, { concurrency: 2, inFlight: 2 })
    expect(sel.spawn).toHaveLength(0)
    expect(sel.deferred).toHaveLength(2)
  })

  test("higher priority is spawned first when over cap", () => {
    const g = graph(
      node({ id: "low", status: "ready", priority: "low" }),
      node({ id: "crit", status: "ready", priority: "critical" }),
    )
    const sel = Orchestrator.selectWave(g, { concurrency: 1 })
    expect(sel.spawn.map((n) => n.id)).toEqual(["crit"])
    expect(sel.deferred.map((n) => n.id)).toEqual(["low"])
  })
})

describe("Orchestrator.selectWave — resolved-vectors ledger (AR3 integration)", () => {
  const resolved: ResolvedVector[] = [
    {
      id: "v1",
      timestamp: "2026-07-15T00:00:00.000Z",
      target: "http://localhost:3000/redirect",
      vector: "open-redirect",
      status: "resolved",
    },
  ]

  test("skips a ready node whose vector is a settled dead end", () => {
    const g = graph(
      node({ id: "dead", status: "ready", target: "http://localhost:3000/redirect", technique: "open-redirect" }),
      node({ id: "live", status: "ready", target: "http://localhost:3000/api", technique: "jwt-alg-confusion" }),
    )
    const sel = Orchestrator.selectWave(g, { concurrency: 5, resolvedVectors: resolved })
    expect(sel.spawn.map((n) => n.id)).toEqual(["live"])
    expect(sel.skipped.map((s) => s.node.id)).toEqual(["dead"])
  })

  test("a merely attempted (not resolved) vector does NOT block a spawn", () => {
    const attempted: ResolvedVector[] = [{ ...resolved[0]!, status: "attempted" }]
    const g = graph(
      node({ id: "retry", status: "ready", target: "http://localhost:3000/redirect", technique: "open-redirect" }),
    )
    const sel = Orchestrator.selectWave(g, { concurrency: 5, resolvedVectors: attempted })
    expect(sel.spawn.map((n) => n.id)).toEqual(["retry"])
    expect(sel.skipped).toHaveLength(0)
  })

  test("unrelated target is not skipped (conservative match)", () => {
    const g = graph(
      node({ id: "other", status: "ready", target: "http://localhost:9999/redirect", technique: "open-redirect" }),
    )
    const sel = Orchestrator.selectWave(g, { concurrency: 5, resolvedVectors: resolved })
    expect(sel.spawn.map((n) => n.id)).toEqual(["other"])
  })
})

describe("Orchestrator.waveStatus — Risk 1: Wave-confirm (no auto-advance)", () => {
  test("quiescent only when nothing is in flight", () => {
    const busy = graph(node({ id: "r", status: "running" }), node({ id: "a", status: "ready" }))
    expect(Orchestrator.waveStatus(busy).quiescent).toBe(false)

    const idle = graph(node({ id: "done", status: "completed" }), node({ id: "a", status: "ready" }))
    expect(Orchestrator.waveStatus(idle).quiescent).toBe(true)
  })

  test("reports counts for the coordinator to steer on", () => {
    const g = graph(
      node({ id: "c1", status: "completed" }),
      node({ id: "f1", status: "failed" }),
      node({ id: "r1", status: "ready" }),
    )
    const s = Orchestrator.waveStatus(g)
    expect(s.completed).toBe(1)
    expect(s.failed).toBe(1)
    expect(s.total).toBe(3)
  })
})

describe("Orchestrator — wave cascade (the flow the concurrency race broke)", () => {
  // Mirrors the real Juice Shop DAG: t1/t3/t6 ready; t2 deps t1; t4/t5 dep t2.
  // Once completions are RECORDED (which store.modifyTaskGraph now does atomically),
  // dependents must become ready and each wave must go quiescent so the coordinator
  // is offered the next one.
  function juiceGraph() {
    return graph(
      node({ id: "t1", status: "ready" }),
      node({ id: "t3", status: "ready" }),
      node({ id: "t6", status: "ready" }),
      node({ id: "t2", dependsOn: ["t1"] }),
      node({ id: "t4", dependsOn: ["t2"] }),
      node({ id: "t5", dependsOn: ["t2"] }),
    )
  }

  test("wave 1 dispatches the 3 dep-free tasks; dependents wait", () => {
    const g = juiceGraph()
    const sel = Orchestrator.selectWave(g, { concurrency: 3 })
    expect(sel.spawn.map((n) => n.id).sort()).toEqual(["t1", "t3", "t6"])
    expect(Orchestrator.waveStatus(g).ready.map((n) => n.id).sort()).toEqual(["t1", "t3", "t6"])
  })

  test("after all 3 complete, t2 becomes ready and the wave is quiescent", () => {
    let g = juiceGraph()
    for (const id of ["t1", "t3", "t6"]) g = TaskGraph.updateTask(g, id, { status: "dispatched" })
    // completions land (order-independent, as concurrent settles would)
    g = TaskGraph.completeTask(g, "t6")
    g = TaskGraph.completeTask(g, "t1")
    g = TaskGraph.completeTask(g, "t3")
    const ws = Orchestrator.waveStatus(g)
    expect(ws.quiescent).toBe(true) // nothing dispatched/running -> coordinator gets the next wave
    expect(ws.ready.map((n) => n.id)).toEqual(["t2"]) // t2's dep (t1) satisfied
    expect(Orchestrator.selectWave(g).spawn.map((n) => n.id)).toEqual(["t2"])
  })

  test("completing t2 unlocks the final wave t4+t5", () => {
    let g = juiceGraph()
    for (const id of ["t1", "t3", "t6"]) g = TaskGraph.completeTask(TaskGraph.updateTask(g, id, { status: "dispatched" }), id)
    g = TaskGraph.completeTask(TaskGraph.updateTask(g, "t2", { status: "dispatched" }), "t2")
    const ws = Orchestrator.waveStatus(g)
    expect(ws.quiescent).toBe(true)
    expect(ws.ready.map((n) => n.id).sort()).toEqual(["t4", "t5"])
  })

  test("a losable completion: if one wave-1 completion is dropped, t2 stays blocked (the bug's signature)", () => {
    let g = juiceGraph()
    for (const id of ["t1", "t3", "t6"]) g = TaskGraph.updateTask(g, id, { status: "dispatched" })
    // simulate the race: t1's completion is LOST (never recorded)
    g = TaskGraph.completeTask(g, "t3")
    g = TaskGraph.completeTask(g, "t6")
    const ws = Orchestrator.waveStatus(g)
    expect(ws.quiescent).toBe(false) // t1 still "dispatched" -> never quiescent (what we saw live)
    expect(ws.ready.map((n) => n.id)).toEqual([]) // t2 never unlocked
    // This is exactly why the atomic modifyTaskGraph fix is required.
  })
})

describe("Orchestrator — premature completion cannot be decided by the harness", () => {
  test("no isComplete/stop export exists", () => {
    // The harness must never end an engagement; guard the API surface.
    expect((Orchestrator as Record<string, unknown>).isComplete).toBeUndefined()
    expect((Orchestrator as Record<string, unknown>).stop).toBeUndefined()
  })

  test("hasOutstandingWork only reports pending work, never a completion verdict", () => {
    const empty = graph()
    expect(Orchestrator.hasOutstandingWork(empty)).toBe(false)
    const pending = graph(node({ id: "a", status: "ready" }))
    expect(Orchestrator.hasOutstandingWork(pending)).toBe(true)
    const running = graph(node({ id: "a", status: "running" }))
    expect(Orchestrator.hasOutstandingWork(running)).toBe(true)
  })
})

describe("Orchestrator.detectStall — A-4 stall watchdog (DAG-deadlock guard)", () => {
  const BASE = Date.parse("2026-07-15T00:00:00.000Z")
  const at = (offsetMs: number) => new Date(BASE + offsetMs).toISOString()

  test("emits a running task older than stallMs with a starved (planned) dependent", () => {
    const g = graph(
      node({ id: "pivot", status: "running", updatedAt: at(0) }),
      node({ id: "exploit", status: "planned", dependsOn: ["pivot"], assignedAgent: "exploiter" }),
    )
    const stalls = Orchestrator.detectStall(g, { stallMs: 300_000, nowMs: BASE + 400_000 })
    expect(stalls).toHaveLength(1)
    expect(stalls[0]!.stalled.id).toBe("pivot")
    expect(stalls[0]!.starvedDependents.map((d) => d.id)).toEqual(["exploit"])
    expect(stalls[0]!.ageMs).toBe(400_000)
  })

  test("dispatched (not yet running) also counts as in-flight", () => {
    const g = graph(
      node({ id: "pivot", status: "dispatched", updatedAt: at(0) }),
      node({ id: "exploit", status: "planned", dependsOn: ["pivot"] }),
    )
    expect(Orchestrator.detectStall(g, { stallMs: 300_000, nowMs: BASE + 400_000 })).toHaveLength(1)
  })

  test("does NOT emit before stallMs elapses", () => {
    const g = graph(
      node({ id: "pivot", status: "running", updatedAt: at(0) }),
      node({ id: "exploit", status: "planned", dependsOn: ["pivot"] }),
    )
    expect(Orchestrator.detectStall(g, { stallMs: 300_000, nowMs: BASE + 100_000 })).toHaveLength(0)
  })

  test("does NOT emit for a long-running task with NO dependents (no false wake)", () => {
    const g = graph(node({ id: "scan", status: "running", updatedAt: at(0) }))
    expect(Orchestrator.detectStall(g, { stallMs: 300_000, nowMs: BASE + 999_000 })).toHaveLength(0)
  })

  test("ignores non-in-flight tasks (completed/ready)", () => {
    const g = graph(
      node({ id: "done", status: "completed", updatedAt: at(0) }),
      node({ id: "dep", status: "planned", dependsOn: ["done"] }),
    )
    // 'done' completed -> 'dep' becomes ready via computeReadiness; nothing in-flight
    expect(Orchestrator.detectStall(g, { stallMs: 1, nowMs: BASE + 999_000 })).toHaveLength(0)
  })

  test("a dependent that is not planned/blocked is not counted as starved", () => {
    const g = graph(
      node({ id: "pivot", status: "running", updatedAt: at(0) }),
      node({ id: "exploit", status: "completed", dependsOn: ["pivot"] }),
    )
    expect(Orchestrator.detectStall(g, { stallMs: 300_000, nowMs: BASE + 400_000 })).toHaveLength(0)
  })

  test("counts a blocked dependent and sorts multiple stalls oldest-first", () => {
    const g = graph(
      node({ id: "old", status: "running", updatedAt: at(0) }),
      node({ id: "recent", status: "running", updatedAt: at(200_000) }),
      node({ id: "d1", status: "planned", dependsOn: ["recent"] }),
      node({ id: "d2", status: "blocked", dependsOn: ["old"] }),
    )
    const stalls = Orchestrator.detectStall(g, { stallMs: 100_000, nowMs: BASE + 500_000 })
    expect(stalls.map((s) => s.stalled.id)).toEqual(["old", "recent"]) // oldest (age 500k) first
  })

  test("#1: does NOT stall an OLD task that is still ACTIVE (recent output)", () => {
    const g = graph(
      node({ id: "pivot", status: "running", updatedAt: at(0) }),
      node({ id: "exploit", status: "planned", dependsOn: ["pivot"] }),
    )
    // dispatched at 0 (age 400k) but produced output at 350k -> idle 50k < 300k -> working, not hung
    const stalls = Orchestrator.detectStall(g, {
      stallMs: 300_000,
      nowMs: BASE + 400_000,
      lastActivityMs: { pivot: BASE + 350_000 },
    })
    expect(stalls).toHaveLength(0)
  })

  test("#1: stalls a task SILENT past stallMs; idleMs reflects silence, ageMs the dispatch age", () => {
    const g = graph(
      node({ id: "pivot", status: "running", updatedAt: at(0) }),
      node({ id: "exploit", status: "planned", dependsOn: ["pivot"] }),
    )
    // last output at 50k; now 400k -> idle 350k >= 300k
    const stalls = Orchestrator.detectStall(g, {
      stallMs: 300_000,
      nowMs: BASE + 400_000,
      lastActivityMs: { pivot: BASE + 50_000 },
    })
    expect(stalls).toHaveLength(1)
    expect(stalls[0]!.idleMs).toBe(350_000)
    expect(stalls[0]!.ageMs).toBe(400_000)
  })

  test("#1: operational role gets a larger threshold via roleStallMultiplier", () => {
    const g = graph(
      node({ id: "shell", status: "running", updatedAt: at(0), assignedAgent: "post_exploit" }),
      node({ id: "dep", status: "planned", dependsOn: ["shell"] }),
    )
    const opts = { stallMs: 300_000, nowMs: BASE + 600_000, roleStallMultiplier: { post_exploit: 4 } }
    // idle 600k < 4*300k = 1.2M -> not stalled
    expect(Orchestrator.detectStall(g, opts)).toHaveLength(0)
    // past 1.2M -> stalled
    expect(Orchestrator.detectStall(g, { ...opts, nowMs: BASE + 1_300_000 })).toHaveLength(1)
  })

  test("#1: sorts most-IDLE first (not most-dispatch-age)", () => {
    const g = graph(
      node({ id: "a", status: "running", updatedAt: at(0) }),
      node({ id: "b", status: "running", updatedAt: at(0) }),
      node({ id: "da", status: "planned", dependsOn: ["a"] }),
      node({ id: "db", status: "planned", dependsOn: ["b"] }),
    )
    // both dispatched at 0; a last-active 100k (idle 400k), b last-active 300k (idle 200k)
    const stalls = Orchestrator.detectStall(g, {
      stallMs: 100_000,
      nowMs: BASE + 500_000,
      lastActivityMs: { a: BASE + 100_000, b: BASE + 300_000 },
    })
    expect(stalls.map((s) => s.stalled.id)).toEqual(["a", "b"]) // a is more idle
  })
})
