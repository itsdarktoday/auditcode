import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { FSUtil } from "@auditcode/core/fs-util"
import DESCRIPTION from "./slither-parse.txt"
import * as Tool from "./tool"
import { spawnSync } from "node:child_process"

export const Parameters = Schema.Struct({
  file_path: Schema.optional(Schema.String).annotate({
    description: "Path to slither JSON output file (e.g. slither-report.json).",
  }),
  raw_json: Schema.optional(Schema.String).annotate({
    description: "Raw JSON string output from slither.",
  }),
  target_path: Schema.optional(Schema.String).annotate({
    description: "Target directory or file to run slither on directly if no JSON provided (runs `slither <target> --json -`).",
  }),
})

export const SlitherParseTool = Tool.define(
  "slither_parse",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const fs = yield* FSUtil.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { file_path?: string; raw_json?: string; target_path?: string },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          let jsonStr = params.raw_json

          if (!jsonStr && params.file_path) {
            const exists = yield* fs.existsSafe(params.file_path).pipe(Effect.orDie)
            if (exists) {
              jsonStr = yield* fs.readFileString(params.file_path).pipe(Effect.orDie)
            }
          }

          if (!jsonStr && params.target_path) {
            try {
              const res = spawnSync("slither", [params.target_path, "--json", "-"], {
                encoding: "utf-8",
                maxBuffer: 20 * 1024 * 1024,
              })
              jsonStr = res.stdout
            } catch (e) {
              return {
                title: "Slither Error",
                metadata: {},
                output: `Failed to execute slither: ${String(e)}`,
              }
            }
          }

          if (!jsonStr) {
            return {
              title: "Error",
              metadata: {},
              output: "Provide either file_path, raw_json, or target_path to run Slither.",
            }
          }

          try {
            const parsed = JSON.parse(jsonStr)
            const detectors = parsed.results?.detectors ?? []
            let addedCount = 0

            const sevMap: Record<string, EngagementSchema.Severity> = {
              High: "high",
              Medium: "medium",
              Low: "low",
              Informational: "info",
              Optimization: "gas",
            }

            const bugClassMap: Record<string, EngagementSchema.BugClass> = {
              "reentrancy-eth": "reentrancy",
              "reentrancy-no-eth": "reentrancy",
              "reentrancy-unlimited-gas": "reentrancy",
              "reentrancy-benign": "reentrancy",
              "reentrancy-events": "reentrancy",
              "arbitrary-send-erc20": "access_control",
              "arbitrary-send-eth": "access_control",
              "unprotected-upgrade": "upgradeability",
              "divide-before-multiply": "math_precision",
              "incorrect-equality": "logic_error",
              "shadowing-state": "logic_error",
              "uninitialized-state": "access_control",
              "controlled-delegatecall": "access_control",
            }

            const lines: string[] = [`Slither Analysis: Found ${detectors.length} detector issues.`]

            for (let i = 0; i < detectors.length; i++) {
              const d = detectors[i]
              const check = d.check ?? "unknown"
              const impact = d.impact ?? "Medium"
              const confidence = d.confidence === "High" ? 0.9 : d.confidence === "Medium" ? 0.7 : 0.5
              const firstElem = d.elements?.[0]
              const contractName = firstElem?.name ?? firstElem?.source_mapping?.filename_short ?? "Contract"
              const lineStart = firstElem?.source_mapping?.lines?.[0]
              const lineEnd = firstElem?.source_mapping?.lines?.[firstElem?.source_mapping?.lines?.length - 1]

              const vulnId = `AC-SLITHER-${i + 1}`
              const severity = sevMap[impact] ?? "medium"
              const bugClass = bugClassMap[check] ?? "other"

              const vuln: EngagementSchema.Vulnerability = {
                id: vulnId,
                title: `[Slither] ${d.description?.split("\n")[0] ?? check}`,
                contract_name: contractName,
                line_start: lineStart,
                line_end: lineEnd,
                severity,
                bug_class: bugClass,
                status: "lead",
                confidence,
                description: d.description ?? "",
                impact: `Detected by Slither rule: ${check} (${impact} impact, ${d.confidence} confidence)`,
                evidence: d.markdown ?? d.description ?? "",
                evidence_items: [
                  {
                    tool: "slither",
                    command: `slither check: ${check}`,
                    output: d.description ?? "",
                    timestamp: new Date().toISOString(),
                    confidence,
                    verification_status: "unverified",
                  },
                ],
                discovered_by: "static_analyst",
              }

              yield* store.addVuln(contractName, vuln)
              addedCount++
              if (addedCount <= 15) {
                lines.push(`  • [${severity.toUpperCase()}] ${vuln.title} on ${contractName}`)
              }
            }

            return {
              title: "Slither Results",
              metadata: { detectors_found: detectors.length, findings_added: addedCount },
              output: lines.join("\n"),
            }
          } catch (err) {
            return {
              title: "Parse Error",
              metadata: {},
              output: `Failed to parse Slither output: ${String(err)}`,
            }
          }
        }),
    }
  }),
)
