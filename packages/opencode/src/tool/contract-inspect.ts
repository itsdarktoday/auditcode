import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { FSUtil } from "@auditcode/core/fs-util"
import DESCRIPTION from "./contract-inspect.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  file_path: Schema.String.annotate({
    description: "Relative or absolute path to the smart contract file (.sol, .vy, or .rs).",
  }),
  auto_register: Schema.optional(Schema.Boolean).annotate({
    description: "Whether to automatically register discovered contracts in audit state. Defaults to true.",
  }),
})

export const ContractInspectTool = Tool.define(
  "contract_inspect",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const fs = yield* FSUtil.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { file_path: string; auto_register?: boolean },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const exists = yield* fs.existsSafe(params.file_path).pipe(Effect.orDie)
          if (!exists) {
            return {
              title: "File Not Found",
              metadata: {},
              output: `Contract file not found at ${params.file_path}`,
            }
          }

          const content = yield* fs.readFileString(params.file_path).pipe(Effect.orDie)
          const lines = content.split("\n")
          const sloc = lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith("//") && !l.trim().startsWith("/*")).length

          const pragmaMatch = content.match(/pragma\s+solidity\s+([^;]+);/)
          const compilerVersion = pragmaMatch ? pragmaMatch[1].trim() : undefined

          const contractMatches = [...content.matchAll(/(contract|abstract\s+contract|interface|library)\s+([A-Za-z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{/g)]
          const discoveredContracts: EngagementSchema.ContractInfo[] = []
          const autoRegister = params.auto_register !== false

          for (const match of contractMatches) {
            const name = match[2]
            const inheritanceStr = match[3] ?? ""
            const inheritance = inheritanceStr
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean)

            let proxyPattern: EngagementSchema.ProxyPattern = "none"
            if (inheritance.includes("UUPSUpgradeable") || content.includes("_authorizeUpgrade")) {
              proxyPattern = "uups"
            } else if (inheritance.includes("TransparentUpgradeableProxy")) {
              proxyPattern = "transparent"
            } else if (content.includes("diamondCut") || inheritance.includes("IDiamondCut")) {
              proxyPattern = "diamond"
            } else if (inheritance.includes("BeaconProxy") || inheritance.includes("UpgradeableBeacon")) {
              proxyPattern = "beacon"
            } else if (inheritance.includes("Clones") || content.includes("cloneDeterministic")) {
              proxyPattern = "minimal_proxy"
            }

            const functions: EngagementSchema.FunctionInfo[] = []
            const funcMatches = [...content.matchAll(/function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*([^{;]*)(?:\{|;)/g)]
            for (const fMatch of funcMatches) {
              const fnName = fMatch[1]
              const paramsStr = fMatch[2]
              const qualifiers = fMatch[3]

              const isPublic = qualifiers.includes("public")
              const isExternal = qualifiers.includes("external")
              const isInternal = qualifiers.includes("internal")
              const isPrivate = qualifiers.includes("private")
              const visibility: "public" | "external" | "internal" | "private" = isExternal
                ? "external"
                : isPublic
                  ? "public"
                  : isPrivate
                    ? "private"
                    : isInternal
                      ? "internal"
                      : "public"

              const isView = qualifiers.includes("view")
              const isPure = qualifiers.includes("pure")
              const isPayable = qualifiers.includes("payable")
              const mutability: "pure" | "view" | "nonpayable" | "payable" = isPure
                ? "pure"
                : isView
                  ? "view"
                  : isPayable
                    ? "payable"
                    : "nonpayable"

              const modifiers = qualifiers
                .split(/\s+/)
                .filter((q) => q && !["public", "external", "internal", "private", "view", "pure", "payable", "virtual", "override", "returns"].includes(q))

              functions.push({
                name: fnName,
                visibility,
                mutability,
                modifiers: modifiers.length > 0 ? modifiers : undefined,
                parameters: paramsStr ? paramsStr.split(",").map((p) => p.trim()) : [],
                is_payable: isPayable,
              })
            }

            const modifiers: EngagementSchema.ModifierInfo[] = []
            const modMatches = [...content.matchAll(/modifier\s+([A-Za-z0-9_]+)\s*(?:\(([^)]*)\))?\s*\{/g)]
            for (const m of modMatches) {
              modifiers.push({
                name: m[1],
                parameters: m[2] ? m[2].split(",").map((p) => p.trim()) : [],
              })
            }

            const events: EngagementSchema.EventInfo[] = []
            const eventMatches = [...content.matchAll(/event\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*;/g)]
            for (const e of eventMatches) {
              events.push({
                name: e[1],
                parameters: e[2] ? e[2].split(",").map((p) => p.trim()) : [],
              })
            }

            const customErrors: EngagementSchema.CustomErrorInfo[] = []
            const errorMatches = [...content.matchAll(/error\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*;/g)]
            for (const err of errorMatches) {
              customErrors.push({
                name: err[1],
                parameters: err[2] ? err[2].split(",").map((p) => p.trim()) : [],
              })
            }

            const contractInfo: EngagementSchema.ContractInfo = {
              name,
              path: params.file_path,
              sloc,
              proxy_pattern: proxyPattern,
              compiler_version: compilerVersion,
              inheritance,
              functions,
              modifiers,
              events,
              custom_errors: customErrors,
            }

            discoveredContracts.push(contractInfo)
            if (autoRegister) {
              yield* store.addContract(name, contractInfo)
            }
          }

          const outLines = [
            `Contract Inspect: ${params.file_path} (${sloc} SLOC, ${discoveredContracts.length} contracts found)`,
            ...discoveredContracts.map((c) => `  • ${c.name} [Proxy: ${c.proxy_pattern ?? "none"}] — ${c.functions?.length ?? 0} functions, ${c.modifiers?.length ?? 0} modifiers`),
          ]

          return {
            title: `Inspect: ${params.file_path}`,
            metadata: { contracts_found: discoveredContracts.length, sloc },
            output: outLines.join("\n"),
          }
        }),
    }
  }),
)
