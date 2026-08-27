import { Effect, Schema } from "effect"
import DESCRIPTION from "./storage-layout.txt"
import * as Tool from "./tool"
import { spawnSync } from "node:child_process"

export const Parameters = Schema.Struct({
  contract_name: Schema.String.annotate({
    description: "Name of the contract to inspect storage layout for (e.g. `Vault`, `LendingPool`).",
  }),
})

export const StorageLayoutTool = Tool.define(
  "storage_layout",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { contract_name: string },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          try {
            const res = spawnSync("forge", ["inspect", params.contract_name, "storage-layout", "--json"], {
              encoding: "utf-8",
              maxBuffer: 20 * 1024 * 1024,
            })

            if (!res.stdout) {
              return {
                title: "Error",
                metadata: {},
                output: `No storage layout output from forge inspect for ${params.contract_name}. Stderr: ${res.stderr}`,
              }
            }

            const layout = JSON.parse(res.stdout)
            const storage = layout.storage ?? []
            const types = layout.types ?? {}
            const hasGap = storage.some((s: any) => s.label?.includes("__gap") || s.label?.includes("gap"))

            const lines = [
              `Storage Layout: ${params.contract_name} (${storage.length} slots used, Storage Gap: ${hasGap ? "Present (Safe)" : "Missing (Hazard)"})`,
            ]

            for (const s of storage.slice(0, 30)) {
              const numBytes = types[s.type]?.numberOfBytes ?? "?"
              lines.push(`  Slot ${s.slot} [offset ${s.offset}, ${numBytes}B]: ${s.label} (${s.type})`)
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
