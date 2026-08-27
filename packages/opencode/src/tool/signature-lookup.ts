import { Effect, Schema } from "effect"
import DESCRIPTION from "./signature-lookup.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  selector: Schema.optional(Schema.String).annotate({
    description: "4-byte function selector hex string (e.g. `0xa9059cbb`, `0x095ea7b3`).",
  }),
  topic: Schema.optional(Schema.String).annotate({
    description: "32-byte event topic hash hex string (e.g. `0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef`).",
  }),
})

export const SignatureLookupTool = Tool.define(
  "signature_lookup",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { selector?: string; topic?: string },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (!params.selector && !params.topic) {
            return {
              title: "Error",
              metadata: {},
              output: "Provide either selector (4-byte) or topic (32-byte hash)",
            }
          }

          const lines: string[] = []

          if (params.selector) {
            const cleanHex = params.selector.startsWith("0x") ? params.selector : `0x${params.selector}`
            const signatures = yield* Effect.promise(async () => {
              try {
                const res = await fetch(`https://api.openchain.xyz/signature-database/v1/lookup?function=${cleanHex}`)
                const json = (await res.json()) as any
                return (json.result?.function?.[cleanHex]?.map((f: any) => f.name) ?? []) as string[]
              } catch {
                return []
              }
            })

            lines.push(`Function Selector ${cleanHex}:`)
            if (signatures.length > 0) {
              for (const sig of signatures) lines.push(`  • ${sig}`)
            } else {
              lines.push("  (no match found in public databases)")
            }
          }

          if (params.topic) {
            const cleanTopic = params.topic.startsWith("0x") ? params.topic : `0x${params.topic}`
            const signatures = yield* Effect.promise(async () => {
              try {
                const res = await fetch(`https://api.openchain.xyz/signature-database/v1/lookup?event=${cleanTopic}`)
                const json = (await res.json()) as any
                return (json.result?.event?.[cleanTopic]?.map((e: any) => e.name) ?? []) as string[]
              } catch {
                return []
              }
            })

            lines.push(`Event Topic ${cleanTopic}:`)
            if (signatures.length > 0) {
              for (const sig of signatures) lines.push(`  • ${sig}`)
            } else {
              lines.push("  (no match found in public databases)")
            }
          }

          return {
            title: "Signature Lookup",
            metadata: {},
            output: lines.join("\n"),
          }
        }),
    }
  }),
)
