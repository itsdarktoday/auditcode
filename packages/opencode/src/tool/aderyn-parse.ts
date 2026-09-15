import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { FSUtil } from "@auditcode/core/fs-util"
import { InstanceState } from "@/effect/instance-state"
import DESCRIPTION from "./aderyn-parse.txt"
import { Tool } from "./tool"
import { spawnSync } from "node:child_process"
import path from "node:path"

export const Parameters = Schema.Struct({
  file_path: Schema.optional(Schema.String).annotate({
    description: "Path to aderyn JSON report file (e.g. report.json).",
  }),
  raw_json: Schema.optional(Schema.String).annotate({
    description: "Raw JSON string from aderyn output.",
  }),
  run_aderyn: Schema.optional(Schema.Boolean).annotate({
    description: "If true, runs `aderyn . --output report.json` in the current workspace.",
  }),
})

export const AderynParseTool = Tool.define(
  "aderyn_parse",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const fs = yield* FSUtil.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { file_path?: string; raw_json?: string; run_aderyn?: boolean },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const cwd = yield* InstanceState.directory.pipe(Effect.orElseSucceed(() => process.cwd()))
          let jsonStr = params.raw_json

          if (params.run_aderyn) {
            try {
              const res = spawnSync("aderyn", [".", "--output", "aderyn-report.json"], {
                cwd,
                encoding: "utf-8",
                timeout: 120000,
                maxBuffer: 20 * 1024 * 1024,
              })
              if (res.error) {
                return {
                  title: "Aderyn Error",
                  metadata: {},
                  output: `Failed to execute aderyn: ${res.error.message}`,
                }
              }
              params.file_path = "aderyn-report.json"
            } catch (err) {
              return {
                title: "Aderyn Error",
                metadata: {},
                output: `Error running aderyn: ${String(err)}`,
              }
            }
          }

          if (!jsonStr && params.file_path) {
            const resolvedPath = path.isAbsolute(params.file_path)
              ? params.file_path
              : path.join(cwd, params.file_path)
            const exists = yield* fs.existsSafe(resolvedPath).pipe(Effect.orDie)
            if (exists) {
              jsonStr = yield* fs.readFileString(resolvedPath).pipe(Effect.orDie)
            }
          }

          if (!jsonStr) {
            return {
              title: "Error",
              metadata: {},
              output: "Provide either file_path, raw_json, or set run_aderyn: true.",
            }
          }

          try {
            const parsed = JSON.parse(jsonStr)
            let addedCount = 0
            const lines: string[] = ["Cyfrin Aderyn Analysis: Ingested detector findings."]

            const severities: Array<"critical" | "high" | "medium" | "low" | "nc"> = ["critical", "high", "medium", "low", "nc"]

            for (const sev of severities) {
              const issues = parsed[sev + "_issues"]?.issues ?? parsed[sev]?.issues ?? []
              for (let i = 0; i < issues.length; i++) {
                const issue = issues[i]
                const title = issue.title ?? issue.detector_name ?? "Aderyn Finding"
                const description = issue.description ?? ""
                const instances = issue.instances ?? []
                const firstInstance = instances[0]
                const contractPath = firstInstance?.contract_path ?? firstInstance?.src ?? "src/Contract.sol"
                const lineStart = firstInstance?.line_no ?? firstInstance?.line
                const contractName = contractPath.split("/").pop()?.replace(".sol", "") ?? "Contract"

                const vulnSeverity: EngagementSchema.Severity =
                  sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "medium" ? "medium" : sev === "low" ? "low" : "info"

                const vulnId = `AC-ADERYN-${sev.toUpperCase()}-${i + 1}`

                const vuln: EngagementSchema.Vulnerability = {
                  id: vulnId,
                  title: `[Aderyn] ${title}`,
                  contract_name: contractName,
                  line_start: lineStart,
                  severity: vulnSeverity,
                  status: "lead",
                  confidence: 0.8,
                  description,
                  impact: `Reported by Cyfrin Aderyn detector: ${title}`,
                  evidence: JSON.stringify(instances.slice(0, 3)),
                  evidence_items: [
                    {
                      tool: "aderyn",
                      command: `aderyn detector: ${title}`,
                      output: description,
                      timestamp: new Date().toISOString(),
                      confidence: 0.8,
                      verification_status: "unverified",
                    },
                  ],
                  discovered_by: "static_analyst",
                }

                yield* store.addVuln(contractName, vuln)
                addedCount++
                if (addedCount <= 15) {
                  lines.push(`  • [${vulnSeverity.toUpperCase()}] ${vuln.title} on ${contractName}`)
                }
              }
            }

            return {
              title: "Aderyn Results",
              metadata: { findings_added: addedCount },
              output: lines.join("\n"),
            }
          } catch (err) {
            return {
              title: "Parse Error",
              metadata: {},
              output: `Failed to parse Aderyn JSON: ${String(err)}`,
            }
          }
        }),
    }
  }),
)
