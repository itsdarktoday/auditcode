import { run as runTui, type TuiInput } from "@auditcode/tui"
import { Global } from "@auditcode/core/global"
import { AppNodeBuilder } from "@auditcode/core/effect/app-node-builder"
import { Effect } from "effect"

export function run(input: TuiInput) {
  return runTui(input).pipe(Effect.provide(AppNodeBuilder.build(Global.node)))
}
