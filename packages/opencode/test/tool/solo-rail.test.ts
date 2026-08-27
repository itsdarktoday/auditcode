import { describe, expect, test } from "bun:test"
import { soloRailStep } from "../../src/tool/tool"

// #2a: the graduated anti-solo-takeover rail decision (pure). Counts a coordinator's
// consecutive operational tool-calls (bash/write/edit) without a dispatch; advisory at
// WARN, hard block at BLOCK; any delegation resets.
describe("#2a soloRailStep — anti-solo-takeover rail", () => {
  const WARN = 6
  const BLOCK = 12

  test("non-coordinator agents are never counted or blocked", () => {
    const r = soloRailStep(5, "exploiter", "bash", {}, WARN, BLOCK)
    expect(r.count).toBe(5)
    expect(r.action.kind).toBe("run")
  })

  test("coordinator non-operational calls (state_query/read) don't count", () => {
    const r = soloRailStep(5, "pentest", "state_query", {}, WARN, BLOCK)
    expect(r.count).toBe(5)
    expect(r.action.kind).toBe("run")
  })

  test("coordinator operational calls increment and run below WARN", () => {
    const r = soloRailStep(2, "pentest", "bash", {}, WARN, BLOCK)
    expect(r.count).toBe(3)
    expect(r.action.kind).toBe("run")
  })

  test("crossing WARN emits an advisory but still runs", () => {
    const r = soloRailStep(WARN, "pentest", "write", {}, WARN, BLOCK) // 6 -> 7
    expect(r.count).toBe(7)
    expect(r.action).toEqual({ kind: "warn", count: 7 })
  })

  test("crossing BLOCK hard-blocks the call", () => {
    const r = soloRailStep(BLOCK, "pentest", "edit", {}, WARN, BLOCK) // 12 -> 13
    expect(r.count).toBe(13)
    expect(r.action).toEqual({ kind: "block", count: 13 })
  })

  test("a task dispatch resets the counter", () => {
    const r = soloRailStep(11, "pentest", "task", {}, WARN, BLOCK)
    expect(r.count).toBe(0)
    expect(r.action.kind).toBe("run")
  })

  test("task_graph plan resets; task_graph status does NOT", () => {
    expect(soloRailStep(11, "pentest", "task_graph", { action: "plan" }, WARN, BLOCK).count).toBe(0)
    const status = soloRailStep(11, "pentest", "task_graph", { action: "status" }, WARN, BLOCK)
    expect(status.count).toBe(11) // not a dispatch, not operational -> unchanged
    expect(status.action.kind).toBe("run")
  })
})
