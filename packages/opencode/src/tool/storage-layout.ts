import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import type { EngagementSchema } from "@auditcode/core/engagement/schema"
import { InstanceState } from "@/effect/instance-state"
import DESCRIPTION from "./storage-layout.txt"
import { Tool } from "./tool"
import { spawnSync } from "node:child_process"

export const Parameters = Schema.Struct({
  contract_name: Schema.String.annotate({
    description: "Name of the contract to inspect storage layout for (e.g. `Vault`, `LendingPool`).",
  }),
})

export const StorageLayoutTool = Tool.define(
  "storage_layout",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { contract_name: string },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const cwd = yield* InstanceState.directory.pipe(Effect.orElseSucceed(() => process.cwd()))
          try {
            const res = spawnSync("forge", ["inspect", params.contract_name, "storage-layout", "--json"], {
              cwd,
              encoding: "utf-8",
              maxBuffer: 20 * 1024 * 1024,
              timeout: 120000,
            })

            if (res.error) {
              return {
                title: "Storage Layout Error",
                metadata: {},
                output: `Failed to execute forge inspect: ${res.error.message}`,
              }
            }

            if (!res.stdout) {
              return {
                title: "Error",
                metadata: {},
                output: `No storage layout output from forge inspect for ${params.contract_name}. Stderr: ${res.stderr || "None"}`,
              }
            }

            const layout = JSON.parse(res.stdout)
            const storage = layout.storage ?? []
            const types = layout.types ?? {}
            const hasGap = storage.some((s: any) => s.label?.includes("__gap") || s.label?.includes("gap"))

            const parsedVars: EngagementSchema.StateVariable[] = storage.map((s: any) => ({
              name: s.label ?? "",
              type: types[s.type]?.label ?? s.type ?? "unknown",
              slot: typeof s.slot === "number" ? s.slot : parseInt(s.slot, 10),
              offset: typeof s.offset === "number" ? s.offset : parseInt(s.offset, 10),
            }))

            const contracts = yield* store.getContracts()
            if (contracts[params.contract_name]) {
              const existingNotes = contracts[params.contract_name].notes ?? []
              const gapNote = hasGap ? "Storage layout verified: gap variable present" : "WARNING: Storage gap missing in upgradeable contract layout"
              const notes = existingNotes.includes(gapNote) ? existingNotes : [...existingNotes, gapNote]
              yield* store.updateContract(params.contract_name, {
                state_variables: parsedVars,
                notes,
              })
            }

            const lines = [
              `Storage Layout: ${params.contract_name} (${storage.length} slots used, Storage Gap: ${hasGap ? "Present (Safe)" : "Missing (Hazard)"})`,
            ]

            for (const s of storage.slice(0, 40)) {
              const numBytes = types[s.type]?.numberOfBytes ?? "?"
              lines.push(`  Slot ${s.slot} [offset ${s.offset}, ${numBytes}B]: ${s.label} (${s.type})`)
            }

            if (storage.length > 40) {
              lines.push(`  ... and ${storage.length - 40} more slots.`)
            }

            return {
              title: `Storage Layout: ${params.contract_name}`,
              metadata: { total_slots: storage.length, has_storage_gap: hasGap },
              output: lines.join("\n"),
            }
          } catch (err) {
            return {
              title: "Storage Layout Error",
              metadata: {},
              output: `Failed to inspect storage layout for ${params.contract_name}: ${String(err)}`,
            }
          }
        }),
    }
  }),
)

