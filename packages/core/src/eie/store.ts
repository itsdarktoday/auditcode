export * as EIEStore from "./store"

import { Context, Effect, Layer, Option, Ref, Schema } from "effect"
import fs from "node:fs"
import path from "node:path"
import os from "node:os"
import { makeGlobalNode } from "../effect/app-node"
import { EIESchema } from "./schema"

export interface PatternMatchResult {
  readonly pattern: EIESchema.Pattern
  readonly score: number
  readonly matchedSignals: readonly string[]
  readonly matchedPrimitives: readonly string[]
}

export interface CounterexampleCheckResult {
  readonly matchedCounterexamples: readonly {
    readonly counterexample: EIESchema.Counterexample
    readonly matchedRule: string
    readonly risk: string
  }[]
  readonly isLikelyFalsePositive: boolean
  readonly reason: string
}

export interface SemanticRoleMatchResult {
  readonly template: EIESchema.AttackTemplate
  readonly roleMap: Record<string, string>
  readonly missingRoles: readonly string[]
  readonly readinessScore: number
}

export interface CandidateFunction {
  readonly name: string
  readonly mutability?: string
  readonly stateWrites?: readonly string[]
  readonly calls?: readonly string[]
}

export interface HypothesisFormulationInput {
  readonly patternId: string
  readonly templateId?: string
  readonly contractFile?: string
  readonly contractName?: string
  readonly targetEvidence: readonly EIESchema.HypothesisEvidence[]
  readonly observedPreconditions?: Record<string, { observed: boolean; reason?: string }>
  readonly codeSnippet?: string
  readonly candidateFunctions?: readonly CandidateFunction[]
}

export interface Interface {
  readonly loadFromDisk: (customDir?: string) => Effect.Effect<{
    patternsLoaded: number
    findingsLoaded: number
    templatesLoaded: number
    counterexamplesLoaded: number
  }>
  readonly getPatterns: () => Effect.Effect<readonly EIESchema.Pattern[]>
  readonly getPattern: (id: string) => Effect.Effect<EIESchema.Pattern | undefined>
  readonly getFindings: () => Effect.Effect<readonly EIESchema.Finding[]>
  readonly getFinding: (id: string) => Effect.Effect<EIESchema.Finding | undefined>
  readonly getTemplates: () => Effect.Effect<readonly EIESchema.AttackTemplate[]>
  readonly getTemplate: (id: string) => Effect.Effect<EIESchema.AttackTemplate | undefined>
  readonly getCounterexamples: () => Effect.Effect<readonly EIESchema.Counterexample[]>
  readonly getCounterexample: (id: string) => Effect.Effect<EIESchema.Counterexample | undefined>

  readonly queryPatterns: (filter: {
    category?: EIESchema.Category
    keywords?: readonly string[]
    primitives?: readonly string[]
    dangerSignals?: readonly string[]
    minScore?: number
  }) => Effect.Effect<readonly PatternMatchResult[]>

  readonly getCounterexamplesForPattern: (patternId: string) => Effect.Effect<readonly EIESchema.Counterexample[]>
  readonly getTemplatesForPattern: (patternId: string) => Effect.Effect<readonly EIESchema.AttackTemplate[]>
  readonly getFindingsForPattern: (patternId: string) => Effect.Effect<readonly EIESchema.Finding[]>

  readonly evaluatePreconditions: (
    patternId: string,
    observedEvidence: Record<string, { observed: boolean; reason?: string }>,
  ) => Effect.Effect<readonly EIESchema.PreconditionCheck[]>

  readonly checkCounterexamples: (
    patternId: string,
    codeSnippet: string,
  ) => Effect.Effect<CounterexampleCheckResult>

  readonly matchSemanticRoles: (
    templateId: string,
    functions: readonly CandidateFunction[],
  ) => Effect.Effect<SemanticRoleMatchResult | undefined>

  readonly formulateHypothesis: (
    input: HypothesisFormulationInput,
  ) => Effect.Effect<EIESchema.Hypothesis>

  readonly savePattern: (pattern: EIESchema.Pattern, targetDir?: string) => Effect.Effect<string>
  readonly saveFinding: (finding: EIESchema.Finding, targetDir?: string) => Effect.Effect<string>
  readonly saveTemplate: (template: EIESchema.AttackTemplate, targetDir?: string) => Effect.Effect<string>
  readonly saveCounterexample: (counterexample: EIESchema.Counterexample, targetDir?: string) => Effect.Effect<string>
}

export class Service extends Context.Service<Service, Interface>()("@auditcode/EIEStore") {}

const decodeJson = Schema.decodeUnknownOption(Schema.UnknownFromJsonString)
const decodePattern = Schema.decodeUnknownOption(EIESchema.Pattern)
const decodeFinding = Schema.decodeUnknownOption(EIESchema.Finding)
const decodeTemplate = Schema.decodeUnknownOption(EIESchema.AttackTemplate)
const decodeCounterexample = Schema.decodeUnknownOption(EIESchema.Counterexample)

function loadJsonSubdir<T>(dirPath: string, decoder: (u: unknown) => Option.Option<T>): T[] {
  if (!fs.existsSync(dirPath)) return []
  const files = fs.readdirSync(dirPath).filter((f) => f.endsWith(".json"))
  return files
    .map((file) => {
      const fullPath = path.join(dirPath, file)
      const content = fs.readFileSync(fullPath, "utf-8")
      const json = Option.getOrUndefined(decodeJson(content))
      if (!json) return undefined
      return Option.getOrUndefined(decoder(json))
    })
    .filter((item): item is T => item !== undefined)
}

function resolveSearchDirs(customDir?: string): string[] {
  const dirs = [
    customDir,
    path.join(process.cwd(), "data", "eie"),
    "/home/nishan/auditcode/data/eie",
    path.join(os.homedir(), ".auditcode", "eie"),
  ].filter((d): d is string => d !== undefined && fs.existsSync(d))
  return [...new Set(dirs)]
}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const patternsRef = yield* Ref.make<readonly EIESchema.Pattern[]>([])
    const findingsRef = yield* Ref.make<readonly EIESchema.Finding[]>([])
    const templatesRef = yield* Ref.make<readonly EIESchema.AttackTemplate[]>([])
    const counterexamplesRef = yield* Ref.make<readonly EIESchema.Counterexample[]>([])

    const loadAll = (customDir?: string) =>
      Effect.gen(function* () {
        const searchDirs = resolveSearchDirs(customDir)
        const patternsMap = new Map<string, EIESchema.Pattern>()
        const findingsMap = new Map<string, EIESchema.Finding>()
        const templatesMap = new Map<string, EIESchema.AttackTemplate>()
        const counterexamplesMap = new Map<string, EIESchema.Counterexample>()

        for (const dir of searchDirs) {
          const loadedPatterns = loadJsonSubdir(path.join(dir, "patterns"), decodePattern)
          for (const item of loadedPatterns) patternsMap.set(item.id, item)

          const loadedFindings = loadJsonSubdir(path.join(dir, "findings"), decodeFinding)
          for (const item of loadedFindings) findingsMap.set(item.id, item)

          const loadedTemplates = loadJsonSubdir(path.join(dir, "templates"), decodeTemplate)
          for (const item of loadedTemplates) templatesMap.set(item.id, item)

          const loadedCounterexamples = loadJsonSubdir(path.join(dir, "counterexamples"), decodeCounterexample)
          for (const item of loadedCounterexamples) counterexamplesMap.set(item.id, item)
        }

        const patterns = [...patternsMap.values()]
        const findings = [...findingsMap.values()]
        const templates = [...templatesMap.values()]
        const counterexamples = [...counterexamplesMap.values()]

        yield* Ref.set(patternsRef, patterns)
        yield* Ref.set(findingsRef, findings)
        yield* Ref.set(templatesRef, templates)
        yield* Ref.set(counterexamplesRef, counterexamples)

        return {
          patternsLoaded: patterns.length,
          findingsLoaded: findings.length,
          templatesLoaded: templates.length,
          counterexamplesLoaded: counterexamples.length,
        }
      })

    // Initial best-effort discovery load
    yield* loadAll()

    return Service.of({
      loadFromDisk: Effect.fn("EIEStore.loadFromDisk")(function* (customDir) {
        return yield* loadAll(customDir)
      }),

      getPatterns: Effect.fn("EIEStore.getPatterns")(function* () {
        return yield* Ref.get(patternsRef)
      }),

      getPattern: Effect.fn("EIEStore.getPattern")(function* (id) {
        const patterns = yield* Ref.get(patternsRef)
        return patterns.find((p) => p.id === id)
      }),

      getFindings: Effect.fn("EIEStore.getFindings")(function* () {
        return yield* Ref.get(findingsRef)
      }),

      getFinding: Effect.fn("EIEStore.getFinding")(function* (id) {
        const findings = yield* Ref.get(findingsRef)
        return findings.find((f) => f.id === id)
      }),

      getTemplates: Effect.fn("EIEStore.getTemplates")(function* () {
        return yield* Ref.get(templatesRef)
      }),

      getTemplate: Effect.fn("EIEStore.getTemplate")(function* (id) {
        const templates = yield* Ref.get(templatesRef)
        return templates.find((t) => t.id === id)
      }),

      getCounterexamples: Effect.fn("EIEStore.getCounterexamples")(function* () {
        return yield* Ref.get(counterexamplesRef)
      }),

      getCounterexample: Effect.fn("EIEStore.getCounterexample")(function* (id) {
        const counterexamples = yield* Ref.get(counterexamplesRef)
        return counterexamples.find((c) => c.id === id)
      }),

      queryPatterns: Effect.fn("EIEStore.queryPatterns")(function* (filter) {
        const allPatterns = yield* Ref.get(patternsRef)
        const minScore = filter.minScore ?? 10
        const keywordsLower = (filter.keywords ?? []).map((k) => k.toLowerCase())
        const primitivesLower = (filter.primitives ?? []).map((p) => p.toLowerCase())
        const signalsLower = (filter.dangerSignals ?? []).map((s) => s.toLowerCase())

        return allPatterns
          .map((pattern) => {
            const categoryScore = filter.category && pattern.category === filter.category ? 35 : 0
            const matchedPrimitives = pattern.primitives_affected.filter((prim) =>
              primitivesLower.includes(prim.toLowerCase()),
            )
            const primitiveScore = matchedPrimitives.length * 20

            const allPatternSignals = [
              ...(pattern.danger_signals.ast_nodes ?? []),
              ...(pattern.danger_signals.function_calls ?? []),
              ...(pattern.danger_signals.storage_access ?? []),
              ...(pattern.danger_signals.keywords ?? []),
            ]
            const matchedSignals = allPatternSignals.filter((sig) =>
              signalsLower.some((s) => sig.toLowerCase().includes(s) || s.includes(sig.toLowerCase())),
            )
            const signalScore = matchedSignals.length * 15

            const searchableText = `${pattern.name} ${pattern.root_cause.mechanism} ${pattern.root_cause.type} ${(pattern.danger_signals.keywords ?? []).join(" ")}`.toLowerCase()
            const matchedKeywords = keywordsLower.filter((kw) => searchableText.includes(kw))
            const keywordScore = matchedKeywords.length * 10

            const score = categoryScore + primitiveScore + signalScore + keywordScore
            return {
              pattern,
              score,
              matchedSignals,
              matchedPrimitives,
            }
          })
          .filter((r) => r.score >= minScore)
          .sort((a, b) => b.score - a.score)
      }),

      getCounterexamplesForPattern: Effect.fn("EIEStore.getCounterexamplesForPattern")(function* (patternId) {
        const all = yield* Ref.get(counterexamplesRef)
        return all.filter((c) => c.pattern_id === patternId)
      }),

      getTemplatesForPattern: Effect.fn("EIEStore.getTemplatesForPattern")(function* (patternId) {
        const all = yield* Ref.get(templatesRef)
        return all.filter((t) => t.pattern_id === patternId)
      }),

      getFindingsForPattern: Effect.fn("EIEStore.getFindingsForPattern")(function* (patternId) {
        const all = yield* Ref.get(findingsRef)
        return all.filter((f) => f.pattern_id === patternId)
      }),

      evaluatePreconditions: Effect.fn("EIEStore.evaluatePreconditions")(function* (patternId, observedEvidence) {
        const patterns = yield* Ref.get(patternsRef)
        const pattern = patterns.find((p) => p.id === patternId)
        if (!pattern) return []

        return pattern.preconditions.map((precond) => {
          const evidenceEntry = observedEvidence[precond.id]
          if (evidenceEntry) {
            return {
              condition_id: precond.id,
              description: precond.description,
              status: evidenceEntry.observed ? ("confirmed" as const) : ("disproven" as const),
              evidence: evidenceEntry.reason,
            }
          }
          return {
            condition_id: precond.id,
            description: precond.description,
            status: "unconfirmed" as const,
            evidence: undefined,
          }
        })
      }),

      checkCounterexamples: Effect.fn("EIEStore.checkCounterexamples")(function* (patternId, codeSnippet) {
        const allCounterexamples = yield* Ref.get(counterexamplesRef)
        const patternCounterexamples = allCounterexamples.filter((c) => c.pattern_id === patternId)

        if (patternCounterexamples.length === 0 || !codeSnippet.trim()) {
          return {
            matchedCounterexamples: [],
            isLikelyFalsePositive: false,
            reason: "No counterexamples matched.",
          }
        }

        const snippetLower = codeSnippet.toLowerCase()
        const matched = patternCounterexamples
          .map((ce) => {
            const astCheck = ce.rejection_signal?.ast_check?.toLowerCase()
            const storageCheck = ce.rejection_signal?.storage_check?.toLowerCase()
            const revertSig = ce.rejection_signal?.revert_signature?.toLowerCase()
            const mechanism = ce.mitigating_mechanism.toLowerCase()

            const astMatch = astCheck && snippetLower.includes(astCheck)
            const storageMatch = storageCheck && snippetLower.includes(storageCheck)
            const revertMatch = revertSig && snippetLower.includes(revertSig)
            const mechanismMatch = snippetLower.includes(mechanism)

            const rule = astMatch
              ? `AST check: ${ce.rejection_signal?.ast_check}`
              : storageMatch
                ? `Storage check: ${ce.rejection_signal?.storage_check}`
                : revertMatch
                  ? `Revert signature: ${ce.rejection_signal?.revert_signature}`
                  : mechanismMatch
                    ? `Mitigating mechanism: ${ce.mitigating_mechanism}`
                    : undefined

            if (!rule) return undefined
            return {
              counterexample: ce,
              matchedRule: rule,
              risk: ce.why_attack_fails,
            }
          })
          .filter((m): m is { counterexample: EIESchema.Counterexample; matchedRule: string; risk: string } => m !== undefined)

        const isLikelyFalsePositive = matched.length > 0
        const reason = isLikelyFalsePositive
          ? `Identified counterexample defense(s): ${matched.map((m) => `${m.counterexample.title} (${m.matchedRule})`).join("; ")}`
          : "No counterexample defenses detected in target code."

        return {
          matchedCounterexamples: matched,
          isLikelyFalsePositive,
          reason,
        }
      }),

      matchSemanticRoles: Effect.fn("EIEStore.matchSemanticRoles")(function* (templateId, functions) {
        const templates = yield* Ref.get(templatesRef)
        const template = templates.find((t) => t.id === templateId)
        if (!template) return undefined

        const roleMap: Record<string, string> = {}
        const missingRoles: string[] = []

        const rolePatterns: Record<string, RegExp> = {
          FUND_IN: /deposit|mint|stake|supply|enter|lend|addliquidity/i,
          FUND_OUT: /withdraw|redeem|exit|borrow|removeliquidity|claim/i,
          COLLATERAL_SEIZURE: /liquidate|seize|foreclose/i,
          PRICE_ORACLE_VIEW: /getprice|latestrounddata|consult|getspotprice|quote|getrate/i,
          PRICE_EXCHANGE: /swap|exchange|trade/i,
          DIRECT_DONATION: /transfer|donate|receive|fallback/i,
          SUPPLY_MINT: /mint/i,
          SUPPLY_BURN: /burn/i,
          STATE_SYNC: /sync|skim|update|settle|rebalance/i,
        }

        for (const [roleKey, roleReq] of Object.entries(template.semantic_role_requirements)) {
          const candidateNames = roleReq.candidate_names ?? []
          const candidateByName = functions.find((fn) =>
            candidateNames.some((cand) => fn.name.toLowerCase() === cand.toLowerCase() || fn.name.toLowerCase().includes(cand.toLowerCase())),
          )

          if (candidateByName) {
            roleMap[roleKey] = candidateByName.name
            continue
          }

          const regex = rolePatterns[roleReq.role]
          const candidateByPattern = regex ? functions.find((fn) => regex.test(fn.name)) : undefined
          if (candidateByPattern) {
            roleMap[roleKey] = candidateByPattern.name
            continue
          }

          missingRoles.push(roleKey)
        }

        const totalReqs = Object.keys(template.semantic_role_requirements).length
        const readinessScore = totalReqs > 0 ? (totalReqs - missingRoles.length) / totalReqs : 1.0

        return {
          template,
          roleMap,
          missingRoles,
          readinessScore,
        }
      }),

      formulateHypothesis: Effect.fn("EIEStore.formulateHypothesis")(function* (input) {
        const patterns = yield* Ref.get(patternsRef)
        const pattern = patterns.find((p) => p.id === input.patternId)
        if (!pattern) {
          return {
            id: `HYP-UNKNOWN-${Date.now()}`,
            pattern_id: input.patternId,
            template_id: input.templateId,
            title: `Unknown Pattern: ${input.patternId}`,
            mechanism: "Pattern not found in Exploit Intelligence Engine store.",
            target_evidence: [...input.targetEvidence],
            precondition_status: [],
            confidence: 0.1,
            status: "draft" as const,
          }
        }

        const preconditionChecks = pattern.preconditions.map((precond) => {
          const evidenceEntry = input.observedPreconditions?.[precond.id]
          if (evidenceEntry) {
            return {
              condition_id: precond.id,
              description: precond.description,
              status: evidenceEntry.observed ? ("confirmed" as const) : ("disproven" as const),
              evidence: evidenceEntry.reason,
            }
          }
          return {
            condition_id: precond.id,
            description: precond.description,
            status: "unconfirmed" as const,
            evidence: undefined,
          }
        })

        const allCounterexamples = yield* Ref.get(counterexamplesRef)
        const patternCounterexamples = allCounterexamples.filter((c) => c.pattern_id === pattern.id)
        const snippetLower = (input.codeSnippet ?? "").toLowerCase()

        const matchedCounterexamples = patternCounterexamples.filter((ce) => {
          if (!snippetLower) return false
          const astCheck = ce.rejection_signal?.ast_check?.toLowerCase()
          const storageCheck = ce.rejection_signal?.storage_check?.toLowerCase()
          const revertSig = ce.rejection_signal?.revert_signature?.toLowerCase()
          const mechanism = ce.mitigating_mechanism.toLowerCase()
          return (
            (astCheck && snippetLower.includes(astCheck)) ||
            (storageCheck && snippetLower.includes(storageCheck)) ||
            (revertSig && snippetLower.includes(revertSig)) ||
            snippetLower.includes(mechanism)
          )
        })

        const hasDisprovenRequired = preconditionChecks.some((c) => c.status === "disproven")
        const confirmedCount = preconditionChecks.filter((c) => c.status === "confirmed").length
        const totalPreconditions = pattern.preconditions.length

        const baseConfidence = 0.65
        const precBonus = totalPreconditions > 0 ? (confirmedCount / totalPreconditions) * 0.3 : 0.1
        const cePenalty = matchedCounterexamples.length > 0 ? 0.5 : 0
        const dispPenalty = hasDisprovenRequired ? 0.4 : 0
        const rawConfidence = baseConfidence + precBonus - cePenalty - dispPenalty
        const confidence = Number(Math.max(0.05, Math.min(0.99, rawConfidence)).toFixed(2))

        const status =
          matchedCounterexamples.length > 0 || hasDisprovenRequired
            ? ("rejected" as const)
            : confirmedCount === totalPreconditions && totalPreconditions > 0
              ? ("validated" as const)
              : ("draft" as const)

        const counterexampleRisk =
          matchedCounterexamples.length > 0
            ? {
                counterexample_id: matchedCounterexamples[0].id,
                risk: matchedCounterexamples[0].why_attack_fails,
              }
            : undefined

        const hypothesis: EIESchema.Hypothesis = {
          id: `HYP-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`,
          pattern_id: pattern.id,
          template_id: input.templateId,
          title: `${pattern.name} in ${input.contractName ?? input.contractFile ?? "Contract"}`,
          mechanism: pattern.root_cause.mechanism,
          target_evidence: [...input.targetEvidence],
          precondition_status: preconditionChecks,
          counterexample_risk: counterexampleRisk,
          confidence,
          status,
        }

        return hypothesis
      }),

      savePattern: Effect.fn("EIEStore.savePattern")(function* (pattern, targetDir) {
        const dir = targetDir ?? path.join(process.cwd(), "data", "eie", "patterns")
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 })
        const filePath = path.join(dir, `${pattern.id}.json`)
        fs.writeFileSync(filePath, JSON.stringify(pattern, undefined, 2), "utf-8")
        yield* Ref.modify(patternsRef, (current) => [
          undefined,
          [...current.filter((p) => p.id !== pattern.id), pattern],
        ])
        return filePath
      }),

      saveFinding: Effect.fn("EIEStore.saveFinding")(function* (finding, targetDir) {
        const dir = targetDir ?? path.join(process.cwd(), "data", "eie", "findings")
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 })
        const filePath = path.join(dir, `${finding.id}.json`)
        fs.writeFileSync(filePath, JSON.stringify(finding, undefined, 2), "utf-8")
        yield* Ref.modify(findingsRef, (current) => [
          undefined,
          [...current.filter((f) => f.id !== finding.id), finding],
        ])
        return filePath
      }),

      saveTemplate: Effect.fn("EIEStore.saveTemplate")(function* (template, targetDir) {
        const dir = targetDir ?? path.join(process.cwd(), "data", "eie", "templates")
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 })
        const filePath = path.join(dir, `${template.id}.json`)
        fs.writeFileSync(filePath, JSON.stringify(template, undefined, 2), "utf-8")
        yield* Ref.modify(templatesRef, (current) => [
          undefined,
          [...current.filter((t) => t.id !== template.id), template],
        ])
        return filePath
      }),

      saveCounterexample: Effect.fn("EIEStore.saveCounterexample")(function* (counterexample, targetDir) {
        const dir = targetDir ?? path.join(process.cwd(), "data", "eie", "counterexamples")
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 })
        const filePath = path.join(dir, `${counterexample.id}.json`)
        fs.writeFileSync(filePath, JSON.stringify(counterexample, undefined, 2), "utf-8")
        yield* Ref.modify(counterexamplesRef, (current) => [
          undefined,
          [...current.filter((c) => c.id !== counterexample.id), counterexample],
        ])
        return filePath
      }),
    })
  }),
)

export const node = makeGlobalNode({
  service: Service,
  layer,
  deps: [],
})
