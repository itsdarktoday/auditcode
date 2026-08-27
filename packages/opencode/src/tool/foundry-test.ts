import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import DESCRIPTION from "./foundry-test.txt"
import * as Tool from "./tool"
import { spawnSync } from "node:child_process"

export const Parameters = Schema.Struct({
  match_test: Schema.optional(Schema.String).annotate({
    description: "Filter to run specific test function (e.g. `test_AuditPoC`, `test_ExploitReentrancy`).",
  }),
  match_contract: Schema.optional(Schema.String).annotate({
    description: "Filter to run tests in a specific contract file (e.g. `PoCTest`, `VaultAuditTest`).",
  }),
  target_vuln_id: Schema.optional(Schema.String).annotate({
    description: "Optional Vulnerability ID in audit state to link this test run to. If test passes proving exploit, updates vuln status to `poc_verified`.",
  }),
  verbosity: Schema.optional(Schema.Literals(["-v", "-vv", "-vvv", "-vvvv", "-vvvvv"])).annotate({
    description: "Verbosity level for Forge traces. Defaults to `-vvvv` for full execution trace.",
  }),
  extra_args: Schema.optional(Schema.Array(Schema.String)).annotate({
    description: "Additional forge test CLI flags (e.g. `['--fork-url', 'https://eth.llamarpc.com']`).",
  }),
})

export const FoundryTestTool = Tool.define(
  "foundry_test",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          match_test?: string
          match_contract?: string
          target_vuln_id?: string
          verbosity?: "-v" | "-vv" | "-vvv" | "-vvvv" | "-vvvvv"
          extra_args?: string[]
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const args = ["test", params.verbosity ?? "-vvvv"]
          if (params.match_test) args.push("--match-test", params.match_test)
          if (params.match_contract) args.push("--match-contract", params.match_contract)
          if (params.extra_args) args.push(...params.extra_args)

          try {
            const res = spawnSync("forge", args, {
              encoding: "utf-8",
              maxBuffer: 20 * 1024 * 1024,
            })

            const stdout = res.stdout ?? ""
            const stderr = res.stderr ?? ""
            const output = (stdout + "\n" + stderr).trim()
            const passed = output.includes("[PASS]") && !output.includes("[FAIL]")

            const pocId = `POC-${params.match_test ?? params.match_contract ?? "test"}`
            yield* store.addPoCTest({
              id: pocId,
              name: params.match_test ?? params.match_contract ?? "Foundry PoC Test",
              target_vuln_id: params.target_vuln_id,
              framework: "foundry",
              command: `forge ${args.join(" ")}`,
              status: passed ? "passed" : "failed",
              execution_trace: output.slice(0, 5000),
            })

            if (params.target_vuln_id && passed) {
              const state = yield* store.get()
              if (state) {
                const vuln = state.vulns?.[params.target_vuln_id]
                if (vuln) {
                  yield* store.updateVuln(vuln.contract_name ?? "contract", params.target_vuln_id, {
                    status: "poc_verified",
                    confidence: 0.99,
                    proof_of_concept: output.slice(0, 3000),
                  })
                }
              }
            }

            const header = passed ? "⚡ Foundry Test: PASSED (PoC Exploit Succeeded)" : "Foundry Test: FAILED"
            return {
              title: header,
              metadata: { passed, command: `forge ${args.join(" ")}` },
              output: `${header}\nCommand: forge ${args.join(" ")}\n\n${output.length > 5000 ? output.slice(0, 5000) + "\n...[truncated]" : output}`,
            }
          } catch (err) {
            return {
              title: "Forge Execution Error",
              metadata: {},
              output: `Failed to execute forge test: ${String(err)}`,
            }
          }
        }),
    }
  }),
)
