import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./phase-control.txt"
import * as Tool from "./tool"

const PHASE_ORDER: EngagementSchema.PentestPhase[] = [
  "scope_recon",
  "static_analysis",
  "threat_modeling",
  "deep_audit",
  "poc_verification",
  "reporting",
]

const PHASE_SKILLS: Record<string, string> = {
  scope_recon: "01_scope_recon",
  static_analysis: "02_static_analysis",
  threat_modeling: "03_threat_modeling",
  deep_audit: "04_deep_audit",
  poc_verification: "05_poc_verification",
  reporting: "06_reporting",
  // Legacy aliases:
  recon: "01_scope_recon",
  enumeration: "02_static_analysis",
  vuln_assess: "04_deep_audit",
  exploitation: "05_poc_verification",
  post_exploit: "05_poc_verification",
}

export const Parameters = Schema.Struct({
  action: Schema.Literals(["status", "next", "set"]),
  phase: Schema.optional(
    Schema.Literals([
      "scope_recon",
      "static_analysis",
      "threat_modeling",
      "deep_audit",
      "poc_verification",
      "reporting",
      "recon",
      "enumeration",
      "vuln_assess",
      "exploitation",
      "post_exploit",
    ]),
  ).annotate({
    description: "Target audit phase (required for 'set' action)",
  }),
  force: Schema.optional(Schema.Boolean).annotate({
    description: "Force phase transition even if quality gates are not met (default: false)",
  }),
})

interface QualityGateResult {
  passed: boolean
  warnings: string[]
  missing: string[]
}

function evaluateQualityGate(state: EngagementSchema.State, fromPhase: EngagementSchema.PentestPhase): QualityGateResult {
  const s = EngagementSchema.summary(state)
  const warnings: string[] = []
  const missing: string[] = []

  switch (fromPhase) {
    case "scope_recon":
    case "recon": {
      if (s.contracts_count === 0 && s.hosts_discovered === 0) {
        missing.push("No in-scope contracts or targets registered — run contract_inspect first")
      }
      if (state.scope.targets.length === 0) {
        warnings.push("Scope targets not explicitly defined")
      }
      break
    }
    case "static_analysis":
    case "enumeration": {
      const topVulns = Object.keys(state.vulns ?? {}).length
      if (topVulns === 0 && s.vulnerabilities === 0) {
        warnings.push("No findings recorded from static analysis — run slither_parse or aderyn_parse")
      }
      break
    }
    case "threat_modeling": {
      const actorCount = Object.keys(state.actors ?? {}).length
      const invariantCount = Object.keys(state.invariants ?? {}).length
      if (actorCount === 0) warnings.push("No actor roles defined in Access Control Matrix")
      if (invariantCount === 0) warnings.push("No protocol invariants formalized")
      break
    }
    case "deep_audit":
    case "vuln_assess": {
      const allVulns = [...Object.values(state.vulns ?? {}), ...Object.values(state.hosts).flatMap((h) => h.vulns)]
      const unvalidated = allVulns.filter((v) => v.status === "suspected" || v.status === "lead")
      if (unvalidated.length > 0) {
        warnings.push(`${unvalidated.length} unvalidated candidate lead(s) — spawn critic before moving to PoC verification`)
      }
      break
    }
    case "poc_verification":
    case "exploitation":
    case "post_exploit": {
      const critHigh = [...Object.values(state.vulns ?? {}), ...Object.values(state.hosts).flatMap((h) => h.vulns)].filter(
        (v) => (v.severity === "critical" || v.severity === "high") && v.status !== "false_positive",
      )
      const pocs = Object.keys(state.pocs ?? {}).length
      if (critHigh.length > 0 && pocs === 0) {
        warnings.push(`${critHigh.length} Critical/High finding(s) exist without verified Foundry PoC tests`)
      }
      break
    }
  }

  return {
    passed: missing.length === 0,
    warnings,
    missing,
  }
}

export const PhaseControlTool = Tool.define(
  "phase_control",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) {
            return {
              title: "Error",
              metadata: {},
              output: "No audit engagement loaded. Create or load one with state_update first.",
            }
          }

          const currentPhase = state.current_phase
          const currentIndex = PHASE_ORDER.indexOf(currentPhase)

          if (params.action === "status") {
            const gate = evaluateQualityGate(state, currentPhase)
            const nextPhase = currentIndex >= 0 && currentIndex < PHASE_ORDER.length - 1 ? PHASE_ORDER[currentIndex + 1] : undefined
            const lines = [
              `Current Audit Phase: ${currentPhase.toUpperCase()} (${currentIndex + 1}/${PHASE_ORDER.length})`,
              `Mode: ${state.mode}`,
              nextPhase ? `Next Phase: ${nextPhase}` : "This is the final phase (reporting).",
              "",
              `Quality Gate Status: ${gate.passed ? "PASSED" : "BLOCKED"}`,
            ]
            if (gate.missing.length > 0) {
              lines.push("Blocking Requirements:")
              for (const m of gate.missing) lines.push(`  - ✗ ${m}`)
            }
            if (gate.warnings.length > 0) {
              lines.push("Warnings:")
              for (const w of gate.warnings) lines.push(`  - ! ${w}`)
            }
            return {
              title: `Phase: ${currentPhase}`,
              metadata: { phase: currentPhase, passed: gate.passed },
              output: lines.join("\n"),
            }
          }

          let targetPhase: EngagementSchema.PentestPhase | undefined
          if (params.action === "next") {
            if (currentIndex < 0 || currentIndex >= PHASE_ORDER.length - 1) {
              return {
                title: "Cannot Advance",
                metadata: { phase: currentPhase },
                output: `Already in final phase (${currentPhase}). Cannot advance further.`,
              }
            }
            targetPhase = PHASE_ORDER[currentIndex + 1]
          } else if (params.action === "set") {
            if (!params.phase) {
              return {
                title: "Error",
                metadata: {},
                output: "Error: 'phase' parameter is required when action is 'set'.",
              }
            }
            targetPhase = params.phase as EngagementSchema.PentestPhase
          }

          if (!targetPhase) {
            return { title: "Error", metadata: {}, output: "Invalid phase action." }
          }

          if (targetPhase === currentPhase) {
            return {
              title: `Phase Unchanged: ${currentPhase}`,
              metadata: { phase: currentPhase },
              output: `Already in phase "${currentPhase}".`,
            }
          }

          const gate = evaluateQualityGate(state, currentPhase)
          if (!gate.passed && !params.force) {
            const lines = [
              `Cannot advance from ${currentPhase} to ${targetPhase} — quality gate failed:`,
              ...gate.missing.map((m) => `  - ✗ ${m}`),
              "",
              "Resolve these requirements first, or use force: true to override.",
            ]
            return {
              title: "Quality Gate Blocked",
              metadata: { phase: currentPhase, targetPhase, passed: false },
              output: lines.join("\n"),
            }
          }

          yield* store.setPhase(targetPhase)
          yield* events.publish(PentestEvent.PhaseTransitioned, {
            engagementID: state.id,
            from: currentPhase,
            to: targetPhase,
            timestamp: Date.now(),
          })

          const relevantSkill = PHASE_SKILLS[targetPhase]
          const lines = [
            `Audit Phase changed: ${currentPhase} -> ${targetPhase.toUpperCase()}`,
            !gate.passed && params.force ? "Warning: Quality gate was bypassed with force: true." : "",
            relevantSkill ? `Recommended: Load knowledge skill "${relevantSkill}".` : "",
          ].filter(Boolean)

          return {
            title: `Phase -> ${targetPhase}`,
            metadata: { from: currentPhase, to: targetPhase },
            output: lines.join("\n"),
          }
        }),
    }
  }),
)
