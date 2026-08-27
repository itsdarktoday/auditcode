export * as EngagementContext from "./context"

import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { SystemContext } from "../system-context/index"
import { SystemContextRegistry } from "../system-context/registry"
import { EngagementStore } from "./store"
import { EngagementSchema } from "./schema"

const StateCodec = Schema.toCodecJson(
  Schema.Struct({
    compact: Schema.String,
    phase: EngagementSchema.PentestPhase,
    mode: EngagementSchema.PentestMode,
  }),
)

interface ContextValue {
  compact: string
  phase: EngagementSchema.PentestPhase
  mode: EngagementSchema.PentestMode
}

function formatBaseline(value: ContextValue): string {
  let objLine = ""
  try {
    const parsed = JSON.parse(value.compact)
    if (parsed.objectives_progress) objLine = `  Objectives: ${parsed.objectives_progress}`
  } catch {}
  const lines = [
    "<audit-engagement>",
    `  Phase: ${value.phase}`,
    `  Mode: ${value.mode}`,
    ...(objLine ? [objLine] : []),
    "",
    "Current engagement state:",
    value.compact,
    "</audit-engagement>",
  ]
  return lines.join("\n")
}

function formatUpdate(previous: ContextValue, current: ContextValue): string {
  const changes: string[] = []
  if (previous.phase !== current.phase) changes.push(`Phase changed: ${previous.phase} → ${current.phase}`)
  if (previous.mode !== current.mode) changes.push(`Mode changed: ${previous.mode} → ${current.mode}`)
  const lines = [
    "<audit-engagement-update>",
    ...changes.map((c) => `  ${c}`),
    "",
    "Updated engagement state:",
    current.compact,
    "</audit-engagement-update>",
  ]
  return lines.join("\n")
}

const engagementContextLayer = Layer.effectDiscard(
  Effect.gen(function* () {
    const registry = yield* SystemContextRegistry.Service
    const store = yield* EngagementStore.Service

    const context = SystemContext.make<ContextValue>({
      key: SystemContext.Key.make("audit/engagement"),
      codec: StateCodec,
      load: Effect.gen(function* () {
        const state = yield* store.get()
        if (!state) return SystemContext.unavailable
        return {
          compact: EngagementSchema.toCompactContext(state),
          phase: state.current_phase,
          mode: state.mode,
        }
      }),
      baseline: formatBaseline,
      update: formatUpdate,
    })

    yield* registry.register({ key: SystemContext.Key.make("audit/engagement"), load: Effect.succeed(context) })
  }),
)

export const node = makeLocationNode({
  name: "engagement-context",
  layer: engagementContextLayer,
  deps: [SystemContextRegistry.node, EngagementStore.node],
})
