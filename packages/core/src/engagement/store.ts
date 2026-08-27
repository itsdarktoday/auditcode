export * as EngagementStore from "./store"

import { Context, Effect, Layer, Ref, Schema } from "effect"
import { makeGlobalNode } from "../effect/app-node"
import { EngagementSchema } from "./schema"
import { TaskGraph } from "./task-graph"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

const ENGAGEMENTS_DIR = path.join(os.homedir(), ".auditcode", "engagements")
const LAST_FILE = ".last"
const SELECTED_FILE = ".selected"
const CHANGELOG_FILE = "changelog.json"
const DECISIONS_FILE = "decisions.json"
const AGENT_CONTEXTS_FILE = "agent-contexts.json"
const WORDLISTS_FILE = "wordlists.json"
const FINDINGS_FILE = "findings.md"

function mergeServices(
  existing: readonly EngagementSchema.Service[],
  incoming: readonly EngagementSchema.Service[],
): EngagementSchema.Service[] {
  const byPort = new Map<string, EngagementSchema.Service>()
  for (const svc of existing) {
    byPort.set(`${svc.port}/${svc.protocol ?? "tcp"}`, svc)
  }
  for (const svc of incoming) {
    const key = `${svc.port}/${svc.protocol ?? "tcp"}`
    const prev = byPort.get(key)
    byPort.set(key, prev ? { ...prev, ...svc } : svc)
  }
  return [...byPort.values()]
}

// Merge in-vector sub-attempts, deduping by technique (a repeat of the same
// technique updates its outcome/detail rather than appending a duplicate) and
// capping to the most recent VECTOR_ATTEMPT_LOG_MAX.
function mergeAttemptLog(
  existing: readonly EngagementSchema.VectorAttempt[] | undefined,
  incoming: readonly EngagementSchema.VectorAttempt[] | undefined,
): EngagementSchema.VectorAttempt[] | undefined {
  if (!existing?.length && !incoming?.length) return existing ? [...existing] : undefined
  const byTechnique = new Map<string, EngagementSchema.VectorAttempt>()
  for (const a of existing ?? []) byTechnique.set(a.technique, a)
  for (const a of incoming ?? []) {
    const prev = byTechnique.get(a.technique)
    byTechnique.set(a.technique, prev ? { ...prev, ...a } : a)
  }
  const all = [...byTechnique.values()]
  return all.length > EngagementSchema.VECTOR_ATTEMPT_LOG_MAX
    ? all.slice(all.length - EngagementSchema.VECTOR_ATTEMPT_LOG_MAX)
    : all
}

export interface Interface {
  readonly addContract: (name: string, contract: EngagementSchema.ContractInfo) => Effect.Effect<EngagementSchema.ContractInfo>
  readonly updateContract: (name: string, patch: Partial<EngagementSchema.ContractInfo>) => Effect.Effect<boolean>
  readonly deleteContract: (name: string) => Effect.Effect<boolean>
  readonly getContracts: () => Effect.Effect<Record<string, EngagementSchema.ContractInfo>>
  readonly addInvariant: (invariant: EngagementSchema.Invariant) => Effect.Effect<void>
  readonly updateInvariant: (id: string, patch: Partial<EngagementSchema.Invariant>) => Effect.Effect<boolean>
  readonly deleteInvariant: (id: string) => Effect.Effect<boolean>
  readonly addActorRole: (role: EngagementSchema.ActorRole) => Effect.Effect<void>
  readonly updateActorRole: (roleName: string, patch: Partial<EngagementSchema.ActorRole>) => Effect.Effect<boolean>
  readonly addPoCTest: (poc: EngagementSchema.PoCTest) => Effect.Effect<void>
  readonly updatePoCTest: (id: string, patch: Partial<EngagementSchema.PoCTest>) => Effect.Effect<boolean>
  readonly get: () => Effect.Effect<EngagementSchema.State | undefined>
  readonly save: (state: EngagementSchema.State) => Effect.Effect<void>
  readonly create: (name: string) => Effect.Effect<EngagementSchema.State>
  readonly load: (name: string) => Effect.Effect<EngagementSchema.State | undefined>
  readonly lastEngagement: () => Effect.Effect<string | undefined>
  readonly listEngagements: () => Effect.Effect<string[]>
  readonly addHost: (ip: string, data?: Partial<EngagementSchema.Host>) => Effect.Effect<EngagementSchema.Host>
  readonly deleteHost: (ip: string) => Effect.Effect<boolean>
  readonly addVuln: (hostIp: string, vuln: EngagementSchema.Vulnerability) => Effect.Effect<void>
  readonly updateVuln: (hostIp: string, vulnId: string, patch: Partial<{ -readonly [K in keyof EngagementSchema.Vulnerability]: EngagementSchema.Vulnerability[K] }>) => Effect.Effect<boolean>
  readonly deleteVuln: (hostIp: string, vulnId: string) => Effect.Effect<boolean>
  readonly addCredential: (id: string, cred: Omit<EngagementSchema.Credential, "id">) => Effect.Effect<void>
  readonly deleteCredential: (id: string) => Effect.Effect<boolean>
  readonly addAccess: (hostIp: string, access: EngagementSchema.Access) => Effect.Effect<void>
  readonly setPhase: (phase: EngagementSchema.PentestPhase) => Effect.Effect<void>
  readonly setMode: (mode: EngagementSchema.PentestMode) => Effect.Effect<void>
  readonly updateScope: (scope: Partial<EngagementSchema.Scope>) => Effect.Effect<void>
  readonly getTaskGraph: () => Effect.Effect<TaskGraph.TaskNodes>
  readonly setTaskGraph: (tasks: TaskGraph.TaskNodes) => Effect.Effect<void>
  // Atomic read-modify-write of the task graph. REQUIRED for the deterministic
  // orchestrator: parallel background subagents complete concurrently, and a
  // get()+set() pair interleaves between fibers, losing completion updates (a
  // wave then never reaches quiescent). Ref.modify applies `fn` to the current
  // value in one atomic step and returns the updated graph.
  readonly modifyTaskGraph: (fn: (tasks: TaskGraph.TaskNodes) => TaskGraph.TaskNodes) => Effect.Effect<TaskGraph.TaskNodes>
  readonly setDomain: (domain: EngagementSchema.DomainState) => Effect.Effect<void>
  readonly updateDomain: (patch: Record<string, unknown>) => Effect.Effect<void>
  readonly addObjective: (objective: EngagementSchema.Objective) => Effect.Effect<void>
  readonly updateObjective: (id: string, patch: Record<string, unknown>) => Effect.Effect<void>
  readonly completeObjective: (id: string, evidence?: string) => Effect.Effect<void>
  readonly getChangelog: (since?: string, limit?: number) => Effect.Effect<EngagementSchema.ChangelogEntry[]>
  readonly getChangelogSince: (since: string) => Effect.Effect<EngagementSchema.ChangelogEntry[]>
  readonly markInjected: () => Effect.Effect<string>
  readonly getLastInjectedTimestamp: () => Effect.Effect<string | undefined>
  readonly addRelationship: (rel: EngagementSchema.Relationship) => Effect.Effect<boolean>
  readonly getRelationships: (filter?: { entity_id?: string; rel_type?: string }) => Effect.Effect<readonly EngagementSchema.Relationship[]>
  readonly deleteRelationship: (source_id: string, rel_type: string, target_id: string) => Effect.Effect<boolean>
  // Decision Memory
  readonly addDecision: (decision: EngagementSchema.Decision) => Effect.Effect<void>
  readonly updateDecisionOutcome: (id: string, outcome: string, notes?: string) => Effect.Effect<boolean>
  readonly getDecisions: (limit?: number) => Effect.Effect<EngagementSchema.Decision[]>
  // Alert Queue
  readonly addAlert: (alert: EngagementSchema.Alert) => Effect.Effect<void>
  readonly acknowledgeAlert: (id: string) => Effect.Effect<boolean>
  readonly getActiveAlerts: () => Effect.Effect<EngagementSchema.Alert[]>
  // Artifacts (reusable weapons / loot / scripts)
  readonly addArtifact: (artifact: EngagementSchema.Artifact) => Effect.Effect<void>
  // Live Sessions
  readonly addLiveSession: (session: EngagementSchema.LiveSession) => Effect.Effect<void>
  readonly updateLiveSession: (id: string, patch: Record<string, unknown>) => Effect.Effect<boolean>
  readonly removeLiveSession: (id: string) => Effect.Effect<boolean>
  // Network Segments
  readonly addNetworkSegment: (segment: EngagementSchema.NetworkSegment) => Effect.Effect<void>
  readonly updateNetworkSegment: (id: string, patch: Record<string, unknown>) => Effect.Effect<boolean>
  readonly removeNetworkSegment: (id: string) => Effect.Effect<boolean>
  // Agent Context Carry
  readonly addAgentContext: (summary: EngagementSchema.AgentContextSummary) => Effect.Effect<void>
  readonly getAgentContexts: (agentType: string, limit?: number) => Effect.Effect<EngagementSchema.AgentContextSummary[]>
  readonly getRecentAgentContexts: (limit?: number) => Effect.Effect<EngagementSchema.AgentContextSummary[]>
  // Interrupt Alerts
  readonly drainInterruptAlerts: () => Effect.Effect<EngagementSchema.Alert[]>
  readonly hasInterruptAlerts: () => Effect.Effect<boolean>
  // Wordlist Usage Tracking
  readonly addWordlistUsage: (usage: EngagementSchema.WordlistUsage) => Effect.Effect<boolean>
  readonly getWordlistUsages: (filter?: { host_ip?: string; port?: number; tool_type?: string }) => Effect.Effect<readonly EngagementSchema.WordlistUsage[]>
  // Pause Behavior
  readonly setPauseBehavior: (behavior: EngagementSchema.PauseBehavior) => Effect.Effect<void>
  // Resolved Vectors Ledger (R6 fix)
  readonly addResolvedVector: (vector: EngagementSchema.ResolvedVector) => Effect.Effect<{ created: boolean }>
  readonly getResolvedVectors: (filter?: { target?: string; status?: string }) => Effect.Effect<readonly EngagementSchema.ResolvedVector[]>
  // Goal
  readonly setGoal: (text: string) => Effect.Effect<void>
  readonly updateGoal: (patch: { status?: EngagementSchema.GoalStatus; evidence?: string }) => Effect.Effect<boolean>
  readonly clearGoal: () => Effect.Effect<void>
  // TUI engagement selector
  readonly readSelected: () => Effect.Effect<string | undefined>
}

export class Service extends Context.Service<Service, Interface>()("@auditcode/EngagementStore") {}

function stateFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, "state.json")
}

function changelogFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, CHANGELOG_FILE)
}

function decisionsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, DECISIONS_FILE)
}

function agentContextsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, AGENT_CONTEXTS_FILE)
}

function wordlistsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, WORDLISTS_FILE)
}

function findingsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, FINDINGS_FILE)
}

function lastFilePath(): string {
  return path.join(ENGAGEMENTS_DIR, LAST_FILE)
}

const encode = Schema.encodeSync(EngagementSchema.State)
const decode = Schema.decodeUnknownSync(EngagementSchema.State)

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const stateRef = yield* Ref.make<EngagementSchema.State | undefined>(undefined)
    const changelogRef = yield* Ref.make<EngagementSchema.ChangelogEntry[]>([])
    const decisionsRef = yield* Ref.make<EngagementSchema.Decision[]>([])
    const agentContextsRef = yield* Ref.make<Record<string, EngagementSchema.AgentContextSummary[]>>({})
    const interruptQueueRef = yield* Ref.make<EngagementSchema.Alert[]>([])
    const wordlistsRef = yield* Ref.make<EngagementSchema.WordlistUsage[]>([])
    const lastInjectedRef = yield* Ref.make<string | undefined>(undefined)

    const logChange = (action: string, entityType: string, entityId: string | undefined, summary: string) =>
      Ref.modify(changelogRef, (current) => {
        const entry: EngagementSchema.ChangelogEntry = {
          timestamp: new Date().toISOString(),
          action,
          entity_type: entityType,
          entity_id: entityId,
          summary,
        }
        const updated = [...current, entry]
        const trimmed = updated.length > EngagementSchema.CHANGELOG_MAX_ENTRIES
          ? updated.slice(updated.length - EngagementSchema.CHANGELOG_MAX_ENTRIES)
          : updated
        return [undefined as void, trimmed]
      })

    const persistChangelogEntries = (name: string, entries: EngagementSchema.ChangelogEntry[]) => {
      try {
        const filePath = changelogFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(entries, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // changelog persistence is best-effort
      }
    }

    const loadChangelog = (name: string): EngagementSchema.ChangelogEntry[] => {
      try {
        const filePath = changelogFilePath(name)
        if (!fs.existsSync(filePath)) return []
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as EngagementSchema.ChangelogEntry[]
      } catch {
        return []
      }
    }

    const persistDecisions = (name: string, entries: EngagementSchema.Decision[]) => {
      try {
        const filePath = decisionsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(entries, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // decisions persistence is best-effort
      }
    }

    const loadDecisions = (name: string): EngagementSchema.Decision[] => {
      try {
        const filePath = decisionsFilePath(name)
        if (!fs.existsSync(filePath)) return []
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as EngagementSchema.Decision[]
      } catch {
        return []
      }
    }

    const persistAgentContexts = (name: string, contexts: Record<string, EngagementSchema.AgentContextSummary[]>) => {
      try {
        const filePath = agentContextsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(contexts, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // agent contexts persistence is best-effort
      }
    }

    const loadAgentContexts = (name: string): Record<string, EngagementSchema.AgentContextSummary[]> => {
      try {
        const filePath = agentContextsFilePath(name)
        if (!fs.existsSync(filePath)) return {}
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as Record<string, EngagementSchema.AgentContextSummary[]>
      } catch {
        return {}
      }
    }

    const persistWordlists = (name: string, entries: readonly EngagementSchema.WordlistUsage[]) => {
      try {
        const filePath = wordlistsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(entries, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // wordlist persistence is best-effort
      }
    }

    const loadWordlists = (name: string): EngagementSchema.WordlistUsage[] => {
      try {
        const filePath = wordlistsFilePath(name)
        if (!fs.existsSync(filePath)) return []
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as EngagementSchema.WordlistUsage[]
      } catch {
        return []
      }
    }

    const appendFinding = (name: string, entry: string) => {
      try {
        const filePath = findingsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        if (!fs.existsSync(filePath)) {
          const header = `# Findings Journal\n\n*Auto-generated during engagement "${name}"*\n\n---\n\n`
          fs.writeFileSync(filePath, header, { encoding: "utf-8", mode: 0o600 })
        }
        fs.appendFileSync(filePath, entry + "\n\n", { encoding: "utf-8" })
      } catch {
        // findings journal is best-effort
      }
    }

    const persist = (state: EngagementSchema.State) =>
      Effect.sync(() => {
        const filePath = stateFilePath(state.name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        const json = encode(state)
        fs.writeFileSync(filePath, JSON.stringify(json, undefined, 2), { encoding: "utf-8", mode: 0o600 })
        const lastPath = lastFilePath()
        fs.mkdirSync(path.dirname(lastPath), { recursive: true, mode: 0o700 })
        fs.writeFileSync(lastPath, state.name, { encoding: "utf-8", mode: 0o600 })
      })

    const persistCurrent = Effect.gen(function* () {
      const state = yield* Ref.get(stateRef)
      if (!state) return
      yield* persist(state)
      const entries = yield* Ref.get(changelogRef)
      persistChangelogEntries(state.name, entries)
    })

    const persistDecisionsCurrent = Effect.gen(function* () {
      const state = yield* Ref.get(stateRef)
      if (!state) return
      const decisions = yield* Ref.get(decisionsRef)
      persistDecisions(state.name, decisions)
      const entries = yield* Ref.get(changelogRef)
      persistChangelogEntries(state.name, entries)
    })

    const persistWordlistsCurrent = Effect.gen(function* () {
      const state = yield* Ref.get(stateRef)
      if (!state) return
      const wordlists = yield* Ref.get(wordlistsRef)
      persistWordlists(state.name, wordlists)
      const entries = yield* Ref.get(changelogRef)
      persistChangelogEntries(state.name, entries)
    })

    const readFromDisk = (name: string) =>
      Effect.sync(() => {
        const filePath = stateFilePath(name)
        if (!fs.existsSync(filePath)) return undefined
        const raw = fs.readFileSync(filePath, "utf-8")
        return decode(JSON.parse(raw))
      })

    return Service.of({
      get: () => Ref.get(stateRef),

      addContract: Effect.fn("EngagementStore.addContract")(function* (name, contractData) {
        const result = yield* Ref.modify(stateRef, (current) => {
          if (!current) {
            return [contractData, current]
          }
          const contracts = current.contracts ?? {}
          const existing = contracts[name]
          const contract = existing ? { ...existing, ...contractData } : contractData
          const updated = {
            ...current,
            contracts: { ...contracts, [name]: contract }
          }
          return [contract, updated]
        })
        yield* logChange("add_contract", "contract", name, `Contract ${name} added (${contractData.path})`)
        yield* persistCurrent
        return result
      }),

      updateContract: Effect.fn("EngagementStore.updateContract")(function* (name, patch) {
        const updated = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.contracts || !current.contracts[name]) return [false, current]
          const contracts = { ...current.contracts }
          contracts[name] = { ...contracts[name], ...patch }
          return [true, { ...current, contracts }]
        })
        if (updated) {
          yield* logChange("update_contract", "contract", name, `Contract ${name} updated`)
          yield* persistCurrent
        }
        return updated
      }),

      deleteContract: Effect.fn("EngagementStore.deleteContract")(function* (name) {
        const deleted = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.contracts || !current.contracts[name]) return [false, current]
          const { [name]: _, ...remaining } = current.contracts
          return [true, { ...current, contracts: remaining }]
        })
        if (deleted) {
          yield* logChange("delete_contract", "contract", name, `Contract ${name} deleted`)
          yield* persistCurrent
        }
        return deleted
      }),

      getContracts: Effect.fn("EngagementStore.getContracts")(function* () {
        const state = yield* Ref.get(stateRef)
        return state?.contracts ?? {}
      }),

      addInvariant: Effect.fn("EngagementStore.addInvariant")(function* (invariant) {
        yield* Ref.modify(stateRef, (current) => {
          if (!current) return [undefined, current]
          const invariants = { ...(current.invariants ?? {}), [invariant.id]: invariant }
          return [undefined, { ...current, invariants }]
        })
        yield* logChange("add_invariant", "invariant", invariant.id, `Invariant ${invariant.id}: ${invariant.title}`)
        yield* persistCurrent
      }),

      updateInvariant: Effect.fn("EngagementStore.updateInvariant")(function* (id, patch) {
        const updated = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.invariants || !current.invariants[id]) return [false, current]
          const invariants = { ...current.invariants }
          invariants[id] = { ...invariants[id], ...patch }
          return [true, { ...current, invariants }]
        })
        if (updated) {
          yield* logChange("update_invariant", "invariant", id, `Invariant ${id} updated`)
          yield* persistCurrent
        }
        return updated
      }),

      deleteInvariant: Effect.fn("EngagementStore.deleteInvariant")(function* (id) {
        const deleted = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.invariants || !current.invariants[id]) return [false, current]
          const { [id]: _, ...remaining } = current.invariants
          return [true, { ...current, invariants: remaining }]
        })
        if (deleted) {
          yield* logChange("delete_invariant", "invariant", id, `Invariant ${id} deleted`)
          yield* persistCurrent
        }
        return deleted
      }),

      addActorRole: Effect.fn("EngagementStore.addActorRole")(function* (role) {
        yield* Ref.modify(stateRef, (current) => {
          if (!current) return [undefined, current]
          const actors = { ...(current.actors ?? {}), [role.role_name]: role }
          return [undefined, { ...current, actors }]
        })
        yield* logChange("add_actor_role", "actor", role.role_name, `Actor Role ${role.role_name} added`)
        yield* persistCurrent
      }),

      updateActorRole: Effect.fn("EngagementStore.updateActorRole")(function* (roleName, patch) {
        const updated = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.actors || !current.actors[roleName]) return [false, current]
          const actors = { ...current.actors }
          actors[roleName] = { ...actors[roleName], ...patch }
          return [true, { ...current, actors }]
        })
        if (updated) {
          yield* logChange("update_actor_role", "actor", roleName, `Actor Role ${roleName} updated`)
          yield* persistCurrent
        }
        return updated
      }),

      addPoCTest: Effect.fn("EngagementStore.addPoCTest")(function* (poc) {
        yield* Ref.modify(stateRef, (current) => {
          if (!current) return [undefined, current]
          const pocs = { ...(current.pocs ?? {}), [poc.id]: poc }
          return [undefined, { ...current, pocs }]
        })
        yield* logChange("add_poc", "poc", poc.id, `PoC Test ${poc.name} [${poc.status ?? "pending"}]`)
        yield* persistCurrent
      }),

      updatePoCTest: Effect.fn("EngagementStore.updatePoCTest")(function* (id, patch) {
        const updated = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.pocs || !current.pocs[id]) return [false, current]
          const pocs = { ...current.pocs }
          pocs[id] = { ...pocs[id], ...patch }
          return [true, { ...current, pocs }]
        })
        if (updated) {
          yield* logChange("update_poc", "poc", id, `PoC Test ${id} updated`)
          yield* persistCurrent
        }
        return updated
      }),


      listEngagements: () =>
        Effect.sync(() => {
          if (!fs.existsSync(ENGAGEMENTS_DIR)) return []
          return fs.readdirSync(ENGAGEMENTS_DIR).filter((entry) => {
            if (entry === LAST_FILE) return false
            const stat = fs.statSync(path.join(ENGAGEMENTS_DIR, entry))
            return stat.isDirectory()
          })
        }),

      save: Effect.fn("EngagementStore.save")(function* (state) {
        const updated = { ...state, updated_at: new Date().toISOString() }
        yield* Ref.set(stateRef, updated)
        yield* persist(updated)
        const entries = yield* Ref.get(changelogRef)
        persistChangelogEntries(updated.name, entries)
        const decisions = yield* Ref.get(decisionsRef)
        if (decisions.length > 0) persistDecisions(updated.name, decisions)
        const contexts = yield* Ref.get(agentContextsRef)
        if (Object.keys(contexts).length > 0) persistAgentContexts(updated.name, contexts)
        const wordlists = yield* Ref.get(wordlistsRef)
        if (wordlists.length > 0) persistWordlists(updated.name, wordlists)
      }),

      create: Effect.fn("EngagementStore.create")(function* (name) {
        const state: EngagementSchema.State = {
          id: EngagementSchema.ID.make(crypto.randomUUID().slice(0, 8)),
          name,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          scope: { targets: [], excludes: [], notes: "" },
          hosts: {},
          credentials: {},
          flags: [],
          attack_path: [],
          task_tree: [],
          current_phase: "recon",
          mode: "auto",
          notes: [],
        }
        yield* Ref.set(stateRef, state)
        yield* Ref.set(changelogRef, [])
        yield* Ref.set(decisionsRef, [])
        yield* Ref.set(agentContextsRef, {})
        yield* Ref.set(interruptQueueRef, [])
        yield* Ref.set(wordlistsRef, [])
        yield* persist(state)
        yield* logChange("create_engagement", "engagement", state.id, `Created engagement "${name}"`)
        return state
      }),

      load: Effect.fn("EngagementStore.load")(function* (name) {
        const state = yield* readFromDisk(name)
        if (state) {
          yield* Ref.set(stateRef, state)
          yield* Ref.set(changelogRef, loadChangelog(name))
          yield* Ref.set(decisionsRef, loadDecisions(name))
          yield* Ref.set(agentContextsRef, loadAgentContexts(name))
          yield* Ref.set(interruptQueueRef, [])
          yield* Ref.set(wordlistsRef, loadWordlists(name))
        }
        return state
      }),

      lastEngagement: () =>
        Effect.sync(() => {
          const p = lastFilePath()
          if (!fs.existsSync(p)) return undefined
          return fs.readFileSync(p, "utf-8").trim() || undefined
        }),

      addHost: Effect.fn("EngagementStore.addHost")(function* (ip, data) {
        const result = yield* Ref.modify(stateRef, (current) => {
          if (!current) {
            const fallback = { ip, services: [], vulns: [], access: [], notes: [], ...data } as EngagementSchema.Host
            return [{ host: fallback, isNew: false, modified: false }, current]
          }
          const existing = current.hosts[ip]
          let host: EngagementSchema.Host
          if (existing) {
            const mergedServices = mergeServices(existing.services, data?.services ?? [])
            host = { ...existing, ...data, services: mergedServices, vulns: existing.vulns, access: existing.access, notes: existing.notes }
          } else {
            host = { ip, services: [], vulns: [], access: [], notes: [], ...data } as EngagementSchema.Host
          }
          return [{ host, isNew: !existing, modified: true }, { ...current, hosts: { ...current.hosts, [ip]: host } }]
        })
        if (result.modified) {
          if (result.isNew) {
            yield* logChange("add_host", "host", ip, `Host ${ip}${data?.hostname ? ` (${data.hostname})` : ""} added, ${result.host.services.length} services`)
          }
          yield* persistCurrent
        }
        return result.host
      }),

      deleteHost: Effect.fn("EngagementStore.deleteHost")(function* (ip) {
        const deleted = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.hosts[ip]) return [false, current]
          const { [ip]: _, ...remainingHosts } = current.hosts
          return [true, { ...current, hosts: remainingHosts }]
        })
        if (deleted) {
          yield* logChange("delete_host", "host", ip, `Host ${ip} deleted`)
          yield* persistCurrent
        }
        return deleted
      }),

      addVuln: Effect.fn("EngagementStore.addVuln")(function* (hostIp, vuln) {
        const action = yield* Ref.modify(stateRef, (current) => {
          if (!current) return ["skip" as const, current]
          const host = current.hosts[hostIp]
          if (!host) return ["skip" as const, current]
          const isDupe = host.vulns.some(
            (v) => v.title === vuln.title && v.service_port === vuln.service_port,
          )
          if (isDupe) {
            const updatedVulns = host.vulns.map((v) =>
              v.title === vuln.title && v.service_port === vuln.service_port ? { ...v, ...vuln } : v,
            )
            return ["updated" as const, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: updatedVulns } } }]
          }
          return ["created" as const, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: [...host.vulns, vuln] } } }]
        })
        if (action === "skip") return
        if (action === "created") {
          yield* logChange("add_vuln", "vuln", vuln.id, `[${(vuln.severity ?? "medium").toUpperCase()}] ${vuln.title} on ${hostIp}${vuln.confidence !== undefined ? ` conf:${vuln.confidence}` : ""}`)
          const state = yield* Ref.get(stateRef)
          if (state) {
            const sevIcon: Record<string, string> = { critical: "!!!", high: "!!", medium: "!", low: ".", info: "i" }
            const findingLines = [
              `## ${sevIcon[vuln.severity ?? "medium"] ?? "!"} [${(vuln.severity ?? "medium").toUpperCase()}] ${vuln.title}`,
              `**Time**: ${new Date().toISOString()}`,
              `**Host**: ${hostIp}${vuln.service_port ? `:${vuln.service_port}` : ""}`,
              `**Status**: ${vuln.status ?? "suspected"}${vuln.confidence !== undefined ? ` (confidence: ${(vuln.confidence * 100).toFixed(0)}%)` : ""}`,
              ...(vuln.description ? [`**Description**: ${vuln.description}`] : []),
              ...(vuln.evidence ? [`**Evidence**: \`${vuln.evidence}\``] : []),
              ...(vuln.evidence_items?.length ? [
                `**Evidence Chain**:`,
                ...vuln.evidence_items.map((e) =>
                  `- \`${e.tool}\`${e.source_agent ? ` (${e.source_agent})` : ""}: ${e.command ?? "(no command)"}${e.verification_status ? ` [${e.verification_status}]` : ""}`
                ),
              ] : []),
              `---`,
            ]
            appendFinding(state.name, findingLines.join("\n"))
          }
        }
        yield* persistCurrent
      }),

      updateVuln: Effect.fn("EngagementStore.updateVuln")(function* (hostIp, vulnId, patch) {
        const found = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const host = current.hosts[hostIp]
          if (!host) return [false, current]
          const idx = host.vulns.findIndex((v) => v.id === vulnId)
          if (idx === -1) return [false, current]
          const updatedVulns = [...host.vulns]
          updatedVulns[idx] = { ...updatedVulns[idx]!, ...patch }
          return [true, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: updatedVulns } } }]
        })
        if (found) {
          yield* logChange("update_vuln", "vuln", vulnId, `Vuln ${vulnId} on ${hostIp} updated: ${Object.keys(patch).join(", ")}`)
          yield* persistCurrent
        }
        return found
      }),

      deleteVuln: Effect.fn("EngagementStore.deleteVuln")(function* (hostIp, vulnId) {
        const deleted = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const host = current.hosts[hostIp]
          if (!host) return [false, current]
          const filtered = host.vulns.filter((v) => v.id !== vulnId)
          if (filtered.length === host.vulns.length) return [false, current]
          return [true, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: filtered } } }]
        })
        if (deleted) {
          yield* logChange("delete_vuln", "vuln", vulnId, `Vuln ${vulnId} deleted from ${hostIp}`)
          yield* persistCurrent
        }
        return deleted
      }),

      addCredential: Effect.fn("EngagementStore.addCredential")(function* (id, cred) {
        const isNew = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const wasNew = !current.credentials[id]
          return [wasNew, { ...current, credentials: { ...current.credentials, [id]: { ...cred, id } } }]
        })
        if (isNew) {
          yield* logChange("add_credential", "credential", id, `Credential ${cred.username ?? id} (${cred.cred_type ?? "password"})${cred.confidence !== undefined ? ` conf:${cred.confidence}` : ""}`)
          const state = yield* Ref.get(stateRef)
          if (state) {
            const findingLines = [
              `## Credential Found: ${cred.username ?? id}`,
              `**Time**: ${new Date().toISOString()}`,
              `**Type**: ${cred.cred_type ?? "password"}`,
              `**Source**: ${cred.source ?? "unknown"}`,
              ...(cred.valid_for?.length ? [`**Valid For**: ${cred.valid_for.join(", ")}`] : []),
              ...(cred.confidence !== undefined ? [`**Confidence**: ${(cred.confidence * 100).toFixed(0)}%`] : []),
              ...(cred.domain ? [`**Domain**: ${cred.domain}`] : []),
              `---`,
            ]
            appendFinding(state.name, findingLines.join("\n"))
          }
        }
        yield* persistCurrent
      }),

      deleteCredential: Effect.fn("EngagementStore.deleteCredential")(function* (id) {
        const deleted = yield* Ref.modify(stateRef, (current) => {
          if (!current || !current.credentials[id]) return [false, current]
          const { [id]: _, ...remaining } = current.credentials
          return [true, { ...current, credentials: remaining }]
        })
        if (deleted) {
          yield* logChange("delete_credential", "credential", id, `Credential ${id} deleted`)
          yield* persistCurrent
        }
        return deleted
      }),

      addAccess: Effect.fn("EngagementStore.addAccess")(function* (hostIp, access) {
        const action = yield* Ref.modify(stateRef, (current) => {
          if (!current) return ["skip" as const, current]
          const host = current.hosts[hostIp]
          if (!host) return ["skip" as const, current]
          const isDupe = host.access.some(
            (a) => a.access_type === access.access_type && a.username === access.username,
          )
          if (isDupe) {
            const updatedAccess = host.access.map((a) =>
              a.access_type === access.access_type && a.username === access.username ? { ...a, ...access } : a,
            )
            return ["updated" as const, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, access: updatedAccess } } }]
          }
          return ["created" as const, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, access: [...host.access, access] } } }]
        })
        if (action === "skip") return
        if (action === "created") {
          yield* logChange("add_access", "access", hostIp, `${access.access_type} as ${access.username} (${access.level ?? "user"}) on ${hostIp}${access.confidence !== undefined ? ` conf:${access.confidence}` : ""}`)
          const state = yield* Ref.get(stateRef)
          if (state) {
            const findingLines = [
              `## Access Gained: ${hostIp}`,
              `**Time**: ${new Date().toISOString()}`,
              `**Type**: ${access.access_type}`,
              `**User**: ${access.username}`,
              `**Level**: ${access.level ?? "user"}`,
              ...(access.details ? [`**Details**: ${access.details}`] : []),
              ...(access.credential_id ? [`**Credential**: ${access.credential_id}`] : []),
              `---`,
            ]
            appendFinding(state.name, findingLines.join("\n"))
          }
        }
        yield* persistCurrent
      }),

      setPhase: Effect.fn("EngagementStore.setPhase")(function* (phase) {
        const oldPhase = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [undefined, current]
          return [current.current_phase, { ...current, current_phase: phase }]
        })
        if (oldPhase !== undefined) {
          yield* logChange("set_phase", "phase", phase, `Phase: ${oldPhase} -> ${phase}`)
          yield* persistCurrent
        }
      }),

      setMode: Effect.fn("EngagementStore.setMode")(function* (mode) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          return [true, { ...current, mode }]
        })
        if (modified) {
          yield* logChange("set_mode", "mode", mode, `Mode: ${mode}`)
          yield* persistCurrent
        }
      }),

      updateScope: Effect.fn("EngagementStore.updateScope")(function* (scope) {
        const result = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [{ modified: false, warned: false }, current]
          const patch: Record<string, unknown> = {}
          let warned = false
          if (scope.targets) {
            warned = true
          }
          if (scope.excludes) patch.excludes = scope.excludes
          if (scope.discovered_targets) patch.discovered_targets = scope.discovered_targets
          if (scope.notes !== undefined) patch.notes = scope.notes
          if (Object.keys(patch).length === 0 && !warned) return [{ modified: false, warned: false }, current]
          return [{ modified: Object.keys(patch).length > 0, warned }, { ...current, scope: { ...current.scope, ...patch } as EngagementSchema.Scope }]
        })
        if (result.modified) {
          yield* logChange("update_scope", "scope", "scope", `Scope updated`)
          yield* persistCurrent
        }
        if (result.warned) {
          yield* logChange("update_scope_rejected", "scope", "scope", `Rejected targets modification — use discovered_targets`)
        }
      }),

      getTaskGraph: Effect.fn("EngagementStore.getTaskGraph")(function* () {
        const current = yield* Ref.get(stateRef)
        if (!current?.task_graph) return {} as TaskGraph.TaskNodes
        return current.task_graph as unknown as TaskGraph.TaskNodes
      }),

      setTaskGraph: Effect.fn("EngagementStore.setTaskGraph")(function* (tasks) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          return [true, { ...current, task_graph: tasks as unknown as Record<string, unknown> }]
        })
        if (modified) yield* persistCurrent
      }),

      modifyTaskGraph: Effect.fn("EngagementStore.modifyTaskGraph")(function* (fn) {
        return yield* Ref.modify(stateRef, (current) => {
          if (!current) return [{} as TaskGraph.TaskNodes, current]
          const graph = (current.task_graph ?? {}) as unknown as TaskGraph.TaskNodes
          const updated = fn(graph)
          return [updated, { ...current, task_graph: updated as unknown as Record<string, unknown> }]
        })
      }),

      setDomain: Effect.fn("EngagementStore.setDomain")(function* (domain) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          return [true, { ...current, domain }]
        })
        if (modified) yield* persistCurrent
      }),

      updateDomain: Effect.fn("EngagementStore.updateDomain")(function* (patch) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.domain ?? { domain_name: "" } as EngagementSchema.DomainState
          return [true, { ...current, domain: { ...existing, ...patch } as EngagementSchema.DomainState }]
        })
        if (modified) yield* persistCurrent
      }),

      addObjective: Effect.fn("EngagementStore.addObjective")(function* (objective) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const objectives = current.objectives ?? {}
          return [true, { ...current, objectives: { ...objectives, [objective.id]: objective } }]
        })
        if (modified) yield* persistCurrent
      }),

      updateObjective: Effect.fn("EngagementStore.updateObjective")(function* (id, patch) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const objectives = current.objectives ?? {}
          if (!objectives[id]) return [false, current]
          return [true, { ...current, objectives: { ...objectives, [id]: { ...objectives[id]!, ...patch } } }]
        })
        if (modified) yield* persistCurrent
      }),

      completeObjective: Effect.fn("EngagementStore.completeObjective")(function* (id, evidence) {
        const title = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [undefined, current]
          const objectives = current.objectives ?? {}
          const existing = objectives[id]
          if (!existing) return [undefined, current]
          return [existing.title, {
            ...current,
            objectives: {
              ...objectives,
              [id]: { ...existing, status: "completed" as const, ...(evidence !== undefined ? { evidence } : {}) },
            },
          }]
        })
        if (title !== undefined) {
          yield* logChange("complete_objective", "objective", id, `Objective "${title}" completed`)
          yield* persistCurrent
        }
      }),

      getChangelog: Effect.fn("EngagementStore.getChangelog")(function* (since, limit) {
        let entries = yield* Ref.get(changelogRef)
        if (since) {
          entries = entries.filter((e) => e.timestamp > since)
        }
        if (limit && limit > 0) {
          entries = entries.slice(-limit)
        }
        return entries
      }),

      getChangelogSince: Effect.fn("EngagementStore.getChangelogSince")(function* (since) {
        const entries = yield* Ref.get(changelogRef)
        return entries.filter((e) => e.timestamp > since)
      }),

      markInjected: Effect.fn("EngagementStore.markInjected")(function* () {
        const ts = new Date().toISOString()
        yield* Ref.set(lastInjectedRef, ts)
        return ts
      }),

      getLastInjectedTimestamp: () => Ref.get(lastInjectedRef),

      addRelationship: Effect.fn("EngagementStore.addRelationship")(function* (rel) {
        const added = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.relationships ?? []
          const isDupe = existing.some(
            (r) => r.source_id === rel.source_id && r.rel_type === rel.rel_type && r.target_id === rel.target_id,
          )
          if (isDupe) return [false, current]
          return [true, { ...current, relationships: [...existing, rel] }]
        })
        if (added) {
          yield* logChange("add_relationship", "relationship", `${rel.source_id}->${rel.target_id}`, `${rel.source_type}:${rel.source_id} --[${rel.rel_type}]--> ${rel.target_type}:${rel.target_id}`)
          yield* persistCurrent
        }
        return added
      }),

      getRelationships: Effect.fn("EngagementStore.getRelationships")(function* (filter) {
        const current = yield* Ref.get(stateRef)
        if (!current) return []
        let rels = current.relationships ?? []
        if (filter?.entity_id) {
          const id = filter.entity_id
          rels = rels.filter((r) => r.source_id === id || r.target_id === id)
        }
        if (filter?.rel_type) {
          const rt = filter.rel_type
          rels = rels.filter((r) => r.rel_type === rt)
        }
        return rels
      }),

      deleteRelationship: Effect.fn("EngagementStore.deleteRelationship")(function* (sourceId, relType, targetId) {
        const deleted = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.relationships ?? []
          const filtered = existing.filter(
            (r) => !(r.source_id === sourceId && r.rel_type === relType && r.target_id === targetId),
          )
          if (filtered.length === existing.length) return [false, current]
          return [true, { ...current, relationships: filtered }]
        })
        if (deleted) {
          yield* logChange("delete_relationship", "relationship", `${sourceId}->${targetId}`, `Deleted ${relType} edge`)
          yield* persistCurrent
        }
        return deleted
      }),

      // --- Decision Memory ---
      addDecision: Effect.fn("EngagementStore.addDecision")(function* (decision) {
        yield* Ref.modify(decisionsRef, (current) => {
          const updated = [...current, decision]
          const trimmed = updated.length > EngagementSchema.DECISIONS_MAX_ENTRIES
            ? updated.slice(updated.length - EngagementSchema.DECISIONS_MAX_ENTRIES)
            : updated
          return [undefined as void, trimmed]
        })
        yield* logChange("add_decision", "decision", decision.id, `[${decision.phase}] ${decision.decision}`)
        yield* persistDecisionsCurrent
      }),

      updateDecisionOutcome: Effect.fn("EngagementStore.updateDecisionOutcome")(function* (id, outcome, notes) {
        const found = yield* Ref.modify(decisionsRef, (current) => {
          const idx = current.findIndex((d) => d.id === id)
          if (idx === -1) return [false, current]
          const updated = [...current]
          updated[idx] = { ...updated[idx]!, outcome: outcome as EngagementSchema.DecisionOutcome, ...(notes ? { outcome_notes: notes } : {}) }
          return [true, updated]
        })
        if (found) {
          yield* logChange("update_decision", "decision", id, `Outcome: ${outcome}${notes ? ` — ${notes}` : ""}`)
          yield* persistDecisionsCurrent
        }
        return found
      }),

      getDecisions: Effect.fn("EngagementStore.getDecisions")(function* (limit) {
        const entries = yield* Ref.get(decisionsRef)
        return limit ? entries.slice(-limit) : entries
      }),

      // --- Alert Queue ---
      addAlert: Effect.fn("EngagementStore.addAlert")(function* (alert) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.alerts ?? []
          const now = Date.now()
          const active = existing.filter((a) => {
            if (a.acknowledged) return false
            const ttl = (a.ttl_minutes ?? EngagementSchema.ALERTS_DEFAULT_TTL_MINUTES) * 60 * 1000
            return now - new Date(a.timestamp).getTime() < ttl
          })
          const capped = active.length >= EngagementSchema.ALERTS_MAX_ACTIVE
            ? [...active.slice(1), alert]
            : [...active, alert]
          return [true, { ...current, alerts: capped }]
        })
        if (!modified) return
        if (alert.priority === "interrupt") {
          yield* Ref.modify(interruptQueueRef, (queue) => [undefined as void, [...queue, alert]])
        }
        yield* logChange("add_alert", "alert", alert.id, `[${alert.severity.toUpperCase()}]${alert.priority === "interrupt" ? " [INTERRUPT]" : ""} ${alert.title}${alert.source_agent ? ` from:${alert.source_agent}` : ""}`)
        yield* persistCurrent
      }),

      acknowledgeAlert: Effect.fn("EngagementStore.acknowledgeAlert")(function* (id) {
        const found = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.alerts ?? []
          const idx = existing.findIndex((a) => a.id === id)
          if (idx === -1) return [false, current]
          const updated = [...existing]
          updated[idx] = { ...updated[idx]!, acknowledged: true }
          return [true, { ...current, alerts: updated }]
        })
        if (found) yield* persistCurrent
        return found
      }),

      getActiveAlerts: Effect.fn("EngagementStore.getActiveAlerts")(function* () {
        const current = yield* Ref.get(stateRef)
        if (!current) return []
        return EngagementSchema.activeAlerts(current)
      }),

      // --- Live Sessions ---
      addLiveSession: Effect.fn("EngagementStore.addLiveSession")(function* (session) {
        const isNew = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.live_sessions ?? []
          const isDupe = existing.some((s) => s.id === session.id)
          if (isDupe) {
            const updated = existing.map((s) => s.id === session.id ? { ...s, ...session } : s)
            return [false, { ...current, live_sessions: updated }]
          }
          return [true, { ...current, live_sessions: [...existing, session] }]
        })
        if (isNew) {
          yield* logChange("add_session", "live_session", session.id, `${session.session_type} on ${session.host_ip}${session.port ? `:${session.port}` : ""} as ${session.username ?? "?"}`)
        }
        yield* persistCurrent
      }),

      addArtifact: Effect.fn("EngagementStore.addArtifact")(function* (artifact) {
        const isNew = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.artifacts ?? []
          const idx = existing.findIndex((a) => a.id === artifact.id || a.path === artifact.path)
          if (idx !== -1) {
            const updated = [...existing]
            updated[idx] = { ...updated[idx]!, ...artifact }
            return [false, { ...current, artifacts: updated }]
          }
          const next = [...existing, artifact].slice(-EngagementSchema.ARTIFACTS_MAX)
          return [true, { ...current, artifacts: next }]
        })
        if (isNew) {
          yield* logChange("add_artifact", "artifact", artifact.id, `${artifact.type}: ${artifact.name} @ ${artifact.path}`)
        }
        yield* persistCurrent
      }),

      updateLiveSession: Effect.fn("EngagementStore.updateLiveSession")(function* (id, patch) {
        const found = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.live_sessions ?? []
          const idx = existing.findIndex((s) => s.id === id)
          if (idx === -1) return [false, current]
          const updated = [...existing]
          updated[idx] = { ...updated[idx]!, ...patch } as EngagementSchema.LiveSession
          return [true, { ...current, live_sessions: updated }]
        })
        if (found) yield* persistCurrent
        return found
      }),

      removeLiveSession: Effect.fn("EngagementStore.removeLiveSession")(function* (id) {
        const removed = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.live_sessions ?? []
          const filtered = existing.filter((s) => s.id !== id)
          if (filtered.length === existing.length) return [false, current]
          return [true, { ...current, live_sessions: filtered }]
        })
        if (removed) {
          yield* logChange("remove_session", "live_session", id, `Session ${id} removed`)
          yield* persistCurrent
        }
        return removed
      }),

      // --- Network Segments ---
      addNetworkSegment: Effect.fn("EngagementStore.addNetworkSegment")(function* (segment) {
        const isNew = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.network_segments ?? []
          const isDupe = existing.some((s) => s.id === segment.id)
          if (isDupe) {
            const updated = existing.map((s) => s.id === segment.id ? { ...s, ...segment } : s)
            return [false, { ...current, network_segments: updated }]
          }
          return [true, { ...current, network_segments: [...existing, segment] }]
        })
        if (isNew) {
          yield* logChange("add_segment", "network_segment", segment.id, `${segment.cidr}${segment.vlan !== undefined ? ` VLAN:${segment.vlan}` : ""}${segment.pivot_host ? ` via ${segment.pivot_host}` : ""}`)
        }
        yield* persistCurrent
      }),

      updateNetworkSegment: Effect.fn("EngagementStore.updateNetworkSegment")(function* (id, patch) {
        const found = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.network_segments ?? []
          const idx = existing.findIndex((s) => s.id === id)
          if (idx === -1) return [false, current]
          const updated = [...existing]
          updated[idx] = { ...updated[idx]!, ...patch } as EngagementSchema.NetworkSegment
          return [true, { ...current, network_segments: updated }]
        })
        if (found) yield* persistCurrent
        return found
      }),

      removeNetworkSegment: Effect.fn("EngagementStore.removeNetworkSegment")(function* (id) {
        const removed = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const existing = current.network_segments ?? []
          const filtered = existing.filter((s) => s.id !== id)
          if (filtered.length === existing.length) return [false, current]
          return [true, { ...current, network_segments: filtered }]
        })
        if (removed) {
          yield* logChange("remove_segment", "network_segment", id, `Segment ${id} removed`)
          yield* persistCurrent
        }
        return removed
      }),

      // --- Agent Context Carry ---
      addAgentContext: Effect.fn("EngagementStore.addAgentContext")(function* (summary) {
        const all = yield* Ref.get(agentContextsRef)
        const existing = all[summary.agent_type] ?? []
        const updated = [...existing, summary]
        const trimmed = updated.length > EngagementSchema.AGENT_CONTEXT_MAX_PER_TYPE
          ? updated.slice(updated.length - EngagementSchema.AGENT_CONTEXT_MAX_PER_TYPE)
          : updated
        const newAll = { ...all, [summary.agent_type]: trimmed }
        yield* Ref.set(agentContextsRef, newAll)
        const state = yield* Ref.get(stateRef)
        if (state) persistAgentContexts(state.name, newAll)
      }),

      getAgentContexts: Effect.fn("EngagementStore.getAgentContexts")(function* (agentType, limit) {
        const all = yield* Ref.get(agentContextsRef)
        const entries = all[agentType] ?? []
        return limit ? entries.slice(-limit) : entries
      }),

      // Newest contexts across ALL agent types, so a fresh subagent sees what
      // OTHER specialists already did (cross-type dedup), not only its own kind.
      getRecentAgentContexts: Effect.fn("EngagementStore.getRecentAgentContexts")(function* (limit) {
        const all = yield* Ref.get(agentContextsRef)
        const flat = Object.values(all).flat()
        flat.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0))
        return limit ? flat.slice(0, limit) : flat
      }),

      // --- Interrupt Alerts ---
      drainInterruptAlerts: Effect.fn("EngagementStore.drainInterruptAlerts")(function* () {
        const alerts = yield* Ref.get(interruptQueueRef)
        if (alerts.length > 0) {
          yield* Ref.set(interruptQueueRef, [])
        }
        return alerts
      }),

      hasInterruptAlerts: Effect.fn("EngagementStore.hasInterruptAlerts")(function* () {
        const alerts = yield* Ref.get(interruptQueueRef)
        return alerts.length > 0
      }),

      // --- Wordlist Usage Tracking ---
      addWordlistUsage: Effect.fn("EngagementStore.addWordlistUsage")(function* (usage) {
        const added = yield* Ref.modify(wordlistsRef, (current) => {
          const isDupe = current.some(
            (w) => w.host_ip === usage.host_ip && w.port === usage.port && w.tool_type === usage.tool_type && w.wordlist_path === usage.wordlist_path,
          )
          if (isDupe) return [false, current]
          const updated = [...current, usage]
          const trimmed = updated.length > EngagementSchema.WORDLISTS_MAX_ENTRIES
            ? updated.slice(updated.length - EngagementSchema.WORDLISTS_MAX_ENTRIES)
            : updated
          return [true, trimmed]
        })
        if (added) {
          yield* logChange("record_wordlist", "wordlist", `${usage.host_ip}:${usage.port}`, `${usage.tool_type}: ${usage.wordlist_path}`)
          yield* persistWordlistsCurrent
        }
        return added
      }),

      getWordlistUsages: Effect.fn("EngagementStore.getWordlistUsages")(function* (filter) {
        let entries: readonly EngagementSchema.WordlistUsage[] = yield* Ref.get(wordlistsRef)
        if (filter?.host_ip) {
          const ip = filter.host_ip
          entries = entries.filter((w) => w.host_ip === ip)
        }
        if (filter?.port !== undefined) {
          const p = filter.port
          entries = entries.filter((w) => w.port === p)
        }
        if (filter?.tool_type) {
          const tt = filter.tool_type
          entries = entries.filter((w) => w.tool_type === tt)
        }
        return entries
      }),

      // --- Pause Behavior ---
      setPauseBehavior: Effect.fn("EngagementStore.setPauseBehavior")(function* (behavior) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          return [true, { ...current, pause_on_finding: behavior }]
        })
        if (modified) {
          yield* logChange("set_pause", "pause", behavior, `Pause on finding: ${behavior}`)
          yield* persistCurrent
        }
      }),

      addResolvedVector: Effect.fn("EngagementStore.addResolvedVector")(function* (vector) {
        const result = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [{ created: false }, current]
          const existing = current.resolved_vectors ?? []
          const idx = existing.findIndex(
            (v) => v.target === vector.target && v.vector === vector.vector,
          )
          let next: EngagementSchema.ResolvedVector[]
          let created: boolean
          if (idx >= 0) {
            const prev = existing[idx]!
            const merged: EngagementSchema.ResolvedVector = {
              ...prev,
              status: vector.status,
              timestamp: vector.timestamp,
              attempts: (prev.attempts ?? 1) + 1,
              tested_by: vector.tested_by ?? prev.tested_by,
              evidence: vector.evidence ?? prev.evidence,
              revisit_when: vector.revisit_when ?? prev.revisit_when,
              attempt_log: mergeAttemptLog(prev.attempt_log, vector.attempt_log),
            }
            next = [...existing]
            next[idx] = merged
            created = false
          } else {
            next = [...existing, { ...vector, attempts: vector.attempts ?? 1, attempt_log: mergeAttemptLog(undefined, vector.attempt_log) }]
            created = true
          }
          const trimmed = next.length > EngagementSchema.RESOLVED_VECTORS_MAX
            ? next.slice(next.length - EngagementSchema.RESOLVED_VECTORS_MAX)
            : next
          return [{ created }, { ...current, resolved_vectors: trimmed }]
        })
        yield* logChange(
          "record_vector",
          "vector",
          vector.target,
          `[${vector.status.toUpperCase()}] ${vector.target} :: ${vector.vector}${result.created ? "" : " (re-probe)"}`,
        )
        yield* persistCurrent
        return result
      }),

      getResolvedVectors: Effect.fn("EngagementStore.getResolvedVectors")(function* (filter) {
        const current = yield* Ref.get(stateRef)
        if (!current) return []
        let vectors = current.resolved_vectors ?? []
        if (filter?.target) vectors = vectors.filter((v) => v.target === filter.target)
        if (filter?.status) vectors = vectors.filter((v) => v.status === filter.status)
        return vectors
      }),

      // --- Goal ---
      setGoal: Effect.fn("EngagementStore.setGoal")(function* (text) {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          const goal: EngagementSchema.Goal = {
            text,
            status: "active",
            set_at: new Date().toISOString(),
          }
          return [true, { ...current, goal }]
        })
        if (modified) {
          yield* logChange("set_goal", "goal", "goal", `Goal set: ${text}`)
          yield* persistCurrent
        }
      }),

      updateGoal: Effect.fn("EngagementStore.updateGoal")(function* (patch) {
        const found = yield* Ref.modify(stateRef, (current) => {
          if (!current?.goal) return [false, current]
          const updated = { ...current.goal }
          if (patch.status) (updated as Record<string, unknown>).status = patch.status
          if (patch.evidence !== undefined) (updated as Record<string, unknown>).evidence = patch.evidence
          if (patch.status === "achieved") (updated as Record<string, unknown>).achieved_at = new Date().toISOString()
          return [true, { ...current, goal: updated as EngagementSchema.Goal }]
        })
        if (found) {
          yield* logChange("update_goal", "goal", "goal", `Goal ${patch.status ?? "updated"}${patch.evidence ? `: ${patch.evidence.slice(0, 80)}` : ""}`)
          yield* persistCurrent
        }
        return found
      }),

      clearGoal: Effect.fn("EngagementStore.clearGoal")(function* () {
        const modified = yield* Ref.modify(stateRef, (current) => {
          if (!current) return [false, current]
          return [true, { ...current, goal: undefined }]
        })
        if (modified) {
          yield* logChange("clear_goal", "goal", "goal", `Goal cleared`)
          yield* persistCurrent
        }
      }),

      readSelected: Effect.fn("EngagementStore.readSelected")(function* () {
        const selectedPath = path.join(ENGAGEMENTS_DIR, SELECTED_FILE)
        try {
          const value = fs.readFileSync(selectedPath, "utf-8").trim()
          fs.unlinkSync(selectedPath)
          return value || undefined
        } catch {
          return undefined
        }
      }),
    })
  }),
)

export const node = makeGlobalNode({
  service: Service,
  layer,
  deps: [],
})
