import fs from "node:fs"
import path from "node:path"
import { spawnSync } from "node:child_process"
import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { InstanceState } from "@/effect/instance-state"
import DESCRIPTION from "./taint-analyze.txt"
import { Tool } from "./tool"

export const Parameters = Schema.Struct({
  file_path: Schema.optional(Schema.String).annotate({
    description: "Relative or absolute path to the Solidity contract file (e.g. `src/Vault.sol`).",
  }),
  contract_name: Schema.optional(Schema.String).annotate({
    description: "Name of the target contract to analyze (e.g. `Vault`, `LendingPool`).",
  }),
  source_code: Schema.optional(Schema.String).annotate({
    description: "Direct Solidity source code to analyze if no file path is provided.",
  }),
  focus_function: Schema.optional(Schema.String).annotate({
    description: "Optional specific function name to isolate and trace in detail (e.g. `withdraw`, `liquidate`).",
  }),
  use_forge_storage: Schema.optional(Schema.Boolean).annotate({
    description: "Whether to run `forge inspect storage-layout` to get exact compiler-resolved storage slots (default: true).",
  }),
})

export interface StateVariableInfo {
  name: string
  type: string
  slot: number
  offset: number
  isConstant: boolean
  isImmutable: boolean
}

export interface TaintSink {
  type: "token_transfer" | "eth_transfer" | "state_write" | "delegatecall" | "selfdestruct" | "assembly"
  target: string
  expression: string
  line: number
  sources: string[]
  guarded: boolean
  sanitizers: string[]
}

export interface HazardInfo {
  type: "cei_violation" | "read_only_reentrancy" | "cross_function_reentrancy" | "unguarded_sink" | "delegatecall_hazard"
  severity: "critical" | "high" | "medium" | "low"
  function_name: string
  line: number
  description: string
  affected_slots: number[]
  exploit_scenario: string
}

export interface FunctionTaintInfo {
  name: string
  visibility: "external" | "public" | "internal" | "private"
  mutability: "pure" | "view" | "nonpayable" | "payable"
  modifiers: string[]
  parameters: Array<{ name: string; type: string }>
  line_start: number
  line_end: number
  sources: string[]
  sanitizers: Array<{ type: "modifier" | "require" | "assert" | "custom_revert"; line: number; condition: string }>
  sinks: TaintSink[]
  state_reads: Array<{ name: string; slot: number; line: number }>
  external_calls: Array<{ call: string; line: number; target: string }>
  state_writes: Array<{ name: string; slot: number; line: number; expression: string }>
  hazards: HazardInfo[]
}

export interface TaintAnalysisResult {
  contract_name: string
  file_path: string
  state_variables: StateVariableInfo[]
  functions: FunctionTaintInfo[]
  hazards: HazardInfo[]
  summary: {
    total_functions: number
    total_slots: number
    total_sinks: number
    unguarded_sinks: number
    cei_violations: number
    read_only_reentrancy_hazards: number
  }
}

interface RawFunctionBlock {
  name: string
  paramsStr: string
  qualifiers: string
  body: string
  lineStart: number
  lineEnd: number
}

// 1. Robust State Variable Extractor
export function parseStateVariables(
  source: string,
  layoutStorage?: Array<{ label?: string; slot: number | string; offset: number | string; type: string }>,
): StateVariableInfo[] {
  const lines = source.split("\n")
  const results: StateVariableInfo[] = []
  let autoSlot = 0

  // If compiler layout is provided by forge, map it
  if (layoutStorage && layoutStorage.length > 0) {
    for (const s of layoutStorage) {
      if (!s.label) continue
      results.push({
        name: s.label,
        type: s.type,
        slot: typeof s.slot === "number" ? s.slot : parseInt(s.slot, 10),
        offset: typeof s.offset === "number" ? s.offset : parseInt(s.offset, 10),
        isConstant: false,
        isImmutable: false,
      })
    }
    return results
  }

  // Pure static extraction fallback
  const clean = source
    .replace(/\/\*[\s\S]*?\*\//g, (m) => "\n".repeat(m.split("\n").length - 1))
    .replace(/\/\/[^\n]*/g, "")

  const cleanLines = clean.split("\n")
  let inContract = false
  let braceDepth = 0

  for (let i = 0; i < cleanLines.length; i++) {
    const line = cleanLines[i].trim()

    if (/^(contract|abstract\s+contract)\s+[A-Za-z0-9_]+/i.test(line)) {
      inContract = true
    }
    for (const char of line) {
      if (char === "{") braceDepth++
      if (char === "}") braceDepth--
    }

    if (!inContract || braceDepth !== 1) continue

    // Filter out functions, events, modifiers, constructors, errors, structs, enums
    if (
      line.startsWith("function ") ||
      line.startsWith("event ") ||
      line.startsWith("modifier ") ||
      line.startsWith("constructor") ||
      line.startsWith("error ") ||
      line.startsWith("struct ") ||
      line.startsWith("enum ") ||
      line.startsWith("using ") ||
      line.startsWith("type ")
    ) {
      continue
    }

    // Match state variable: mapping(...) or type [visibility] [constant|immutable] name [= val];
    const match = line.match(/^([A-Za-z0-9_\[\]]+|mapping\s*\([\s\S]*?\))\s+(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+)*([A-Za-z0-9_]+)\s*(?:=|;)/)
    if (match) {
      const type = match[1].trim()
      const name = match[2].trim()
      const isConstant = line.includes("constant")
      const isImmutable = line.includes("immutable")

      results.push({
        name,
        type,
        slot: isConstant || isImmutable ? -1 : autoSlot++,
        offset: 0,
        isConstant,
        isImmutable,
      })
    }
  }

  return results
}

// 2. Brace-Matching Function Block Extractor
export function extractFunctionsWithBraces(source: string): RawFunctionBlock[] {
  const functions: RawFunctionBlock[] = []
  const fnRegex = /\bfunction\s+([A-Za-z0-9_]+)\s*\(([\s\S]*?)\)\s*([^{;]*)\{/g
  let match: RegExpExecArray | null

  while ((match = fnRegex.exec(source)) !== null) {
    const name = match[1]
    const paramsStr = match[2]
    const qualifiers = match[3]
    const bodyStartIndex = match.index + match[0].length

    // Count braces to find true closing brace
    let depth = 1
    let cur = bodyStartIndex
    while (cur < source.length && depth > 0) {
      const c = source[cur]
      if (c === "{") depth++
      else if (c === "}") depth--
      cur++
    }

    if (depth === 0) {
      const body = source.slice(bodyStartIndex, cur - 1)
      const lineStart = source.slice(0, match.index).split("\n").length
      const lineEnd = source.slice(0, cur).split("\n").length

      functions.push({
        name,
        paramsStr,
        qualifiers,
        body,
        lineStart,
        lineEnd,
      })
    }
  }

  return functions
}

// 3. Taint and Call-Graph Analyzer for a Single Function
export function analyzeFunctionTaint(
  rawFn: RawFunctionBlock,
  stateVars: StateVariableInfo[],
  fullSource: string,
): FunctionTaintInfo {
  // Parse visibility
  const isExternal = rawFn.qualifiers.includes("external")
  const isPublic = rawFn.qualifiers.includes("public")
  const isPrivate = rawFn.qualifiers.includes("private")
  const isInternal = rawFn.qualifiers.includes("internal")
  const visibility: "external" | "public" | "internal" | "private" = isExternal
    ? "external"
    : isPublic
      ? "public"
      : isPrivate
        ? "private"
        : isInternal
          ? "internal"
          : "public"

  // Parse mutability
  const isPure = rawFn.qualifiers.includes("pure")
  const isView = rawFn.qualifiers.includes("view")
  const isPayable = rawFn.qualifiers.includes("payable")
  const mutability: "pure" | "view" | "nonpayable" | "payable" = isPure
    ? "pure"
    : isView
      ? "view"
      : isPayable
        ? "payable"
        : "nonpayable"

  // Parse modifiers
  const modifierMatches = [
    ...rawFn.qualifiers.matchAll(/\b(onlyOwner|onlyRole|nonReentrant|lock|whenNotPaused|auth|requiresAuth|[A-Z][A-Za-z0-9_]*)(?:\([^\)]*\))?/g),
  ]
  const modifiers = modifierMatches.map((m) => m[0].trim()).filter((m) => !["public", "external", "internal", "private", "view", "pure", "payable", "returns", "virtual", "override"].includes(m))

  // Parse parameters (Taint Sources)
  const parameters: Array<{ name: string; type: string }> = []
  if (rawFn.paramsStr.trim()) {
    const rawParams = rawFn.paramsStr.split(",")
    for (const p of rawParams) {
      const parts = p.trim().split(/\s+/)
      if (parts.length >= 2) {
        const type = parts[0].trim()
        const name = parts[parts.length - 1].trim()
        parameters.push({ name, type })
      }
    }
  }

  // Sources
  const sources: string[] = parameters.map((p) => p.name)
  if (rawFn.body.includes("msg.sender")) sources.push("msg.sender")
  if (rawFn.body.includes("msg.value") || isPayable) sources.push("msg.value")
  if (rawFn.body.includes("tx.origin")) sources.push("tx.origin")

  // Sanitizers
  const sanitizers: Array<{ type: "modifier" | "require" | "assert" | "custom_revert"; line: number; condition: string }> = []
  for (const mod of modifiers) {
    sanitizers.push({ type: "modifier", line: rawFn.lineStart, condition: mod })
  }

  const bodyLines = rawFn.body.split("\n")
  const sinks: TaintSink[] = []
  const stateReads: Array<{ name: string; slot: number; line: number }> = []
  const externalCalls: Array<{ call: string; line: number; target: string }> = []
  const stateWrites: Array<{ name: string; slot: number; line: number; expression: string }> = []
  const hazards: HazardInfo[] = []

  const activeSanitizers: string[] = [...modifiers]

  for (let idx = 0; idx < bodyLines.length; idx++) {
    const currentLineNumber = rawFn.lineStart + idx + 1
    const lineText = bodyLines[idx].trim()

    // 1. Sanitizer Checks
    const requireMatch = lineText.match(/require\s*\(([\s\S]*?)\);?/)
    if (requireMatch) {
      const cond = requireMatch[1].split(",")[0].trim()
      sanitizers.push({ type: "require", line: currentLineNumber, condition: cond })
      activeSanitizers.push(`require(${cond})`)
    }
    const assertMatch = lineText.match(/assert\s*\(([\s\S]*?)\);?/)
    if (assertMatch) {
      sanitizers.push({ type: "assert", line: currentLineNumber, condition: assertMatch[1].trim() })
      activeSanitizers.push(`assert(${assertMatch[1].trim()})`)
    }
    if (lineText.includes("revert ") || lineText.match(/revert\s*[A-Za-z0-9_]*\(/)) {
      sanitizers.push({ type: "custom_revert", line: currentLineNumber, condition: lineText })
      activeSanitizers.push(`revert_guard`)
    }

    // 2. State Variable Reads
    for (const v of stateVars) {
      if (v.slot >= 0 && lineText.includes(v.name)) {
        // Exclude if it's strictly a write target: "v.name =" or "v.name +="
        const writeRegex = new RegExp(`^${v.name}\\s*(\\[[^\\]]*\\])?\\s*(\\+|-|\\*|/)?=`)
        if (!writeRegex.test(lineText)) {
          if (!stateReads.some((r) => r.name === v.name && r.line === currentLineNumber)) {
            stateReads.push({ name: v.name, slot: v.slot, line: currentLineNumber })
          }
        }
      }
    }

    // 3. External Calls Detection
    const callMatch =
      lineText.match(/([A-Za-z0-9_]+)\.(call|delegatecall|transfer|send|safeTransfer|safeTransferFrom|transferFrom)\s*(?:\{[^\}]*\})?\s*\(/) ??
      lineText.match(/IERC[A-Za-z0-9_]*\([^\)]*\)\.([A-Za-z0-9_]+)\s*\(/)

    if (callMatch) {
      const target = callMatch[1] ?? "external"
      externalCalls.push({
        call: lineText,
        line: currentLineNumber,
        target,
      })
    }

    // 4. State Variable Writes
    for (const v of stateVars) {
      if (v.slot >= 0) {
        const assignRegex = new RegExp(`\\b${v.name}(?:\\s*\\[[^\\]]*\\])?\\s*(\\+|-|\\*|/)?=`)
        const pushRegex = new RegExp(`\\b${v.name}\\.push\\s*\\(`)
        const deleteRegex = new RegExp(`\\bdelete\\s+${v.name}\\b`)

        if (assignRegex.test(lineText) || pushRegex.test(lineText) || deleteRegex.test(lineText)) {
          stateWrites.push({
            name: v.name,
            slot: v.slot,
            line: currentLineNumber,
            expression: lineText,
          })

          // Record as state write sink
          const isTainted = sources.some((s) => lineText.includes(s))
          sinks.push({
            type: "state_write",
            target: v.name,
            expression: lineText,
            line: currentLineNumber,
            sources: sources.filter((s) => lineText.includes(s)),
            guarded: activeSanitizers.length > 0,
            sanitizers: [...activeSanitizers],
          })
        }
      }
    }

    // 5. Sensitive Sinks Detection
    // ETH Transfer
    if (lineText.includes(".call{value:") || lineText.match(/\.(transfer|send)\s*\(/)) {
      const isTainted = sources.some((s) => lineText.includes(s))
      const guarded = activeSanitizers.length > 0
      sinks.push({
        type: "eth_transfer",
        target: lineText,
        expression: lineText,
        line: currentLineNumber,
        sources: sources.filter((s) => lineText.includes(s)),
        guarded,
        sanitizers: [...activeSanitizers],
      })
      if (isTainted && !guarded) {
        hazards.push({
          type: "unguarded_sink",
          severity: "high",
          function_name: rawFn.name,
          line: currentLineNumber,
          description: `Unguarded ETH transfer sink at line ${currentLineNumber}. Controlled by user inputs (${sources.join(", ")}) without sanitizer.`,
          affected_slots: [],
          exploit_scenario: `Attacker calls ${rawFn.name}() with arbitrary recipient/amount to drain contract balance.`,
        })
      }
    }

    // Token Transfer Sinks
    if (
      lineText.includes("transfer(") ||
      lineText.includes("safeTransfer(") ||
      lineText.includes("transferFrom(") ||
      lineText.includes("safeTransferFrom(")
    ) {
      const isTainted = sources.some((s) => lineText.includes(s))
      const guarded = activeSanitizers.length > 0
      sinks.push({
        type: "token_transfer",
        target: lineText,
        expression: lineText,
        line: currentLineNumber,
        sources: sources.filter((s) => lineText.includes(s)),
        guarded,
        sanitizers: [...activeSanitizers],
      })
    }

    // Delegatecall Sink
    if (lineText.includes(".delegatecall(")) {
      hazards.push({
        type: "delegatecall_hazard",
        severity: "critical",
        function_name: rawFn.name,
        line: currentLineNumber,
        description: `Dangerous delegatecall executed at line ${currentLineNumber}.`,
        affected_slots: stateVars.map((v) => v.slot),
        exploit_scenario: `If target or data is user-influenced, caller can execute selfdestruct or overwrite proxy storage slots.`,
      })
    }
  }

  // 6. Detect Checks-Effects-Interactions (CEI) Violations in this function
  for (const extCall of externalCalls) {
    const writesAfterCall = stateWrites.filter((w) => w.line > extCall.line)
    if (writesAfterCall.length > 0) {
      const affectedSlots = [...new Set(writesAfterCall.map((w) => w.slot))]
      const affectedVars = writesAfterCall.map((w) => `${w.name} (slot ${w.slot}, line ${w.line})`).join(", ")

      hazards.push({
        type: "cei_violation",
        severity: modifiers.includes("nonReentrant") ? "medium" : "high",
        function_name: rawFn.name,
        line: extCall.line,
        description: `Checks-Effects-Interactions (CEI) violation: external call at line ${extCall.line} before state write to ${affectedVars}.`,
        affected_slots: affectedSlots,
        exploit_scenario: `An attacker-controlled contract or fallback hook can re-enter ${rawFn.name}() or another function while ${affectedVars} remains un-updated.`,
      })
    }
  }

  return {
    name: rawFn.name,
    visibility,
    mutability,
    modifiers,
    parameters,
    line_start: rawFn.lineStart,
    line_end: rawFn.lineEnd,
    sources,
    sanitizers,
    sinks,
    state_reads: stateReads,
    external_calls: externalCalls,
    state_writes: stateWrites,
    hazards,
  }
}

// 4. Cross-Function & Read-Only Reentrancy Desynchronization Detector
export function detectStorageDesync(
  functions: FunctionTaintInfo[],
  stateVars: StateVariableInfo[],
): HazardInfo[] {
  const hazards: HazardInfo[] = []

  // Collect all functions that execute external calls before updating state slots
  const ceiViolators = functions.filter((fn) =>
    fn.hazards.some((h) => h.type === "cei_violation"),
  )

  for (const mutator of ceiViolators) {
    const writtenSlotsAfterCalls = new Set<number>()
    for (const call of mutator.external_calls) {
      for (const write of mutator.state_writes) {
        if (write.line > call.line) {
          writtenSlotsAfterCalls.add(write.slot)
        }
      }
    }

    // Now find any VIEW or external READ function that queries these desynchronized slots without a reentrancy guard
    for (const reader of functions) {
      if (reader.name === mutator.name) continue

      const readsDesyncedSlot = reader.state_reads.some((r) => writtenSlotsAfterCalls.has(r.slot))
      if (readsDesyncedSlot) {
        const isView = reader.mutability === "view" || reader.mutability === "pure"
        const lacksGuard = !reader.modifiers.includes("nonReentrant")
        const sharedSlots = [
          ...new Set(reader.state_reads.filter((r) => writtenSlotsAfterCalls.has(r.slot)).map((r) => r.slot)),
        ]
        const varNames = stateVars
          .filter((v) => sharedSlots.includes(v.slot))
          .map((v) => `${v.name} (slot ${v.slot})`)
          .join(", ")

        if (isView && lacksGuard) {
          hazards.push({
            type: "read_only_reentrancy",
            severity: "high",
            function_name: reader.name,
            line: reader.line_start,
            description: `Read-Only Reentrancy Hazard: \`${reader.name}()\` reads ${varNames} without reentrancy guard, while \`${mutator.name}()\` modifies them after external call at line ${mutator.external_calls[0]?.line ?? 0}.`,
            affected_slots: sharedSlots,
            exploit_scenario: `During external callbacks in \`${mutator.name}()\`, third-party protocols or oracles querying \`${reader.name}()\` will read a desynchronized, inconsistent state before accounting settles.`,
          })
        } else if (lacksGuard && !isView) {
          hazards.push({
            type: "cross_function_reentrancy",
            severity: "high",
            function_name: reader.name,
            line: reader.line_start,
            description: `Cross-Function Reentrancy Hazard: \`${reader.name}()\` reads/writes ${varNames} and lacks nonReentrant, while \`${mutator.name}()\` modifies them across external calls.`,
            affected_slots: sharedSlots,
            exploit_scenario: `Attacker can reenter from \`${mutator.name}()\` external call directly into \`${reader.name}()\` to exploit intermediate states.`,
          })
        }
      }
    }
  }

  return hazards
}

// 5. Generate LLM Prompt-Ready Semantic Slice
export function generateSemanticSlice(result: TaintAnalysisResult, focusFunction?: string): string {
  const targetFns = focusFunction
    ? result.functions.filter((f) => f.name.toLowerCase() === focusFunction.toLowerCase())
    : result.functions

  const lines: string[] = [
    `# Semantic Call-Graph & Taint Slices: \`${result.contract_name}\``,
    "",
    `**Scope**: \`${result.file_path}\` | **Slots**: ${result.summary.total_slots} | **Functions**: ${result.summary.total_functions} | **Hazards**: ${result.hazards.length}`,
    "",
    "## 📦 Storage Slot Layout",
    "| Slot | Offset | Variable Name | Type | Modifiers |",
    "|---|---|---|---|---|",
    ...result.state_variables.map(
      (s) =>
        `| ${s.slot >= 0 ? s.slot : "N/A"} | ${s.offset} | \`${s.name}\` | \`${s.type}\` | ${s.isConstant ? "constant" : s.isImmutable ? "immutable" : "storage"} |`,
    ),
    "",
    "---",
    "",
    "## 🔄 Function Execution & Taint Slices",
  ]

  for (const fn of targetFns) {
    const isGuarded = fn.modifiers.length > 0
    lines.push(`### \`${fn.name}(${fn.parameters.map((p) => `${p.type} ${p.name}`).join(", ")})\``)
    lines.push(`- **Visibility**: \`${fn.visibility}\` | **Mutability**: \`${fn.mutability}\``)
    lines.push(`- **Modifiers**: ${fn.modifiers.length ? fn.modifiers.map((m) => `\`${m}\``).join(", ") : "_[none]_"}`)
    lines.push(`- **Taint Sources**: ${fn.sources.length ? fn.sources.map((s) => `\`${s}\``).join(", ") : "_[none]_"}`)

    if (fn.sanitizers.length > 0) {
      lines.push(`- **Sanitizers**:`)
      for (const s of fn.sanitizers) {
        lines.push(`  - [Line ${s.line}] \`${s.condition}\` (${s.type})`)
      }
    }

    if (fn.sinks.length > 0) {
      lines.push(`- **Sinks**:`)
      for (const s of fn.sinks) {
        const badge = s.guarded ? "🟢 Guarded" : "🔴 Unguarded"
        lines.push(`  - [Line ${s.line}] ${badge} \`${s.type}\`: \`${s.expression}\``)
      }
    }

    // Ordered Sequence
    const sequence: Array<{ line: number; text: string }> = [
      ...fn.state_reads.map((r) => ({ line: r.line, text: `[READ] \`${r.name}\` (slot ${r.slot})` })),
      ...fn.external_calls.map((c) => ({ line: c.line, text: `⚠️ [EXTERNAL CALL] \`${c.call}\`` })),
      ...fn.state_writes.map((w) => ({ line: w.line, text: `[WRITE] \`${w.expression}\` (slot ${w.slot})` })),
    ].sort((a, b) => a.line - b.line)

    if (sequence.length > 0) {
      lines.push(`- **Storage & Call Sequence**:`)
      for (const seq of sequence) {
        lines.push(`  ${seq.line}. ${seq.text}`)
      }
    }

    lines.push("")
  }

  lines.push("---")
  lines.push("")
  lines.push("## 🚨 Security Anomalies & Desynchronization Hazards")

  if (result.hazards.length === 0) {
    lines.push("✅ **No CEI violations or Read-Only Reentrancy hazards detected.** All storage interactions follow safe state synchronization.")
  } else {
    lines.push("| Severity | Type | Location | Affected Slots | Description |")
    lines.push("|---|---|---|---|---|")
    for (const h of result.hazards) {
      const badge =
        h.severity === "critical"
          ? "🔴 Critical"
          : h.severity === "high"
            ? "🟠 High"
            : h.severity === "medium"
              ? "🟡 Medium"
              : "🔵 Low"
      lines.push(
        `| ${badge} | \`${h.type}\` | \`${h.function_name}()\` [L${h.line}] | ${h.affected_slots.map((s) => `Slot ${s}`).join(", ") || "N/A"} | ${h.description} |`,
      )
    }

    lines.push("")
    lines.push("### Exploit Scenarios:")
    for (const h of result.hazards) {
      lines.push(`- **${h.function_name}() [${h.type}]**: ${h.exploit_scenario}`)
    }
  }

  return lines.join("\n")
}

export const TaintAnalyzeTool = Tool.define(
  "taint_analyze",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          file_path?: string
          contract_name?: string
          source_code?: string
          focus_function?: string
          use_forge_storage?: boolean
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const cwd = yield* InstanceState.directory.pipe(Effect.orElseSucceed(() => process.cwd()))

          let contractPath = params.file_path
          let contractName = params.contract_name ?? "TargetContract"
          let sourceContent = params.source_code ?? ""

          // Resolve source code from file path or workspace
          if (!sourceContent) {
            if (!contractPath && params.contract_name) {
              const candidates = [
                path.join("src", `${params.contract_name}.sol`),
                path.join("contracts", `${params.contract_name}.sol`),
                `${params.contract_name}.sol`,
              ]
              for (const c of candidates) {
                const full = path.isAbsolute(c) ? c : path.join(cwd, c)
                if (fs.existsSync(full)) {
                  contractPath = c
                  break
                }
              }
            }

            if (contractPath) {
              const fullPath = path.isAbsolute(contractPath) ? contractPath : path.join(cwd, contractPath)
              if (fs.existsSync(fullPath)) {
                sourceContent = fs.readFileSync(fullPath, "utf-8")
                if (!params.contract_name) {
                  contractName = path.basename(contractPath, ".sol")
                }
              }
            }
          }

          if (!sourceContent) {
            return {
              title: "Taint Analysis Error",
              metadata: {},
              output: `Unable to locate contract source code for ${contractName}. Provide \`file_path\` or \`source_code\`.`,
            }
          }

          // Optional Forge storage layout inspection for compiler-resolved slots
          let forgeLayout: any[] | undefined
          if (params.use_forge_storage !== false && params.contract_name) {
            try {
              const res = spawnSync("forge", ["inspect", params.contract_name, "storage-layout", "--json"], {
                cwd,
                encoding: "utf-8",
                timeout: 30000,
              })
              if (res.stdout && res.status === 0) {
                const parsed = JSON.parse(res.stdout)
                forgeLayout = parsed.storage
              }
            } catch {
              // Ignore forge errors; pure static parser will automatically assign sequential slots
            }
          }

          // 1. Extract State Variables & Slots
          const stateVars = parseStateVariables(sourceContent, forgeLayout)

          // 2. Extract and analyze Functions
          const rawFunctions = extractFunctionsWithBraces(sourceContent)
          const functionTaints = rawFunctions.map((raw) => analyzeFunctionTaint(raw, stateVars, sourceContent))

          // 3. Detect Cross-Function & Read-Only Reentrancy Desync
          const crossHazards = detectStorageDesync(functionTaints, stateVars)

          // Combine all hazards
          const allHazards = [...functionTaints.flatMap((f) => f.hazards), ...crossHazards]

          const totalSinks = functionTaints.flatMap((f) => f.sinks).length
          const unguardedSinks = functionTaints.flatMap((f) => f.sinks.filter((s) => !s.guarded)).length
          const ceiViolations = allHazards.filter((h) => h.type === "cei_violation").length
          const readOnlyReentrancies = allHazards.filter((h) => h.type === "read_only_reentrancy").length

          const analysisResult: TaintAnalysisResult = {
            contract_name: contractName,
            file_path: contractPath ?? "memory",
            state_variables: stateVars,
            functions: functionTaints,
            hazards: allHazards,
            summary: {
              total_functions: functionTaints.length,
              total_slots: stateVars.filter((v) => v.slot >= 0).length,
              total_sinks: totalSinks,
              unguarded_sinks: unguardedSinks,
              cei_violations: ceiViolations,
              read_only_reentrancy_hazards: readOnlyReentrancies,
            },
          }

          // Auto-reconcile with EngagementStore if contract exists
          const contracts = yield* store.getContracts()
          if (contracts[contractName]) {
            const hazardNotes = allHazards.map((h) => `[${h.severity.toUpperCase()}] ${h.type} in ${h.function_name}(): ${h.description}`)
            const existingNotes = contracts[contractName].notes ?? []
            yield* store.updateContract(contractName, {
              notes: [...new Set([...existingNotes, ...hazardNotes])],
            })
          }

          const outputMarkdown = generateSemanticSlice(analysisResult, params.focus_function)

          const title = `Semantic Taint & Call-Graph: ${contractName} (${allHazards.length} hazards detected)`

          return {
            title,
            metadata: {
              contract_name: contractName,
              hazards_count: allHazards.length,
              cei_violations: ceiViolations,
              read_only_reentrancies: readOnlyReentrancies,
              total_sinks: totalSinks,
            },
            output: outputMarkdown,
          }
        }),
    }
  }),
)
