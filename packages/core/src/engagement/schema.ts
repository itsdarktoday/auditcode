export * as EngagementSchema from "./schema"

import { Schema } from "effect"

export const ID = Schema.String.pipe(Schema.brand("Engagement.ID"))
export type ID = typeof ID.Type

export const Severity = Schema.Literals(["critical", "high", "medium", "low", "gas", "info"])
export type Severity = typeof Severity.Type

export const VulnStatus = Schema.Literals([
  "suspected",
  "lead",
  "confirmed",
  "poc_verified",
  "false_positive",
  "mitigated",
  "exploited",
])
export type VulnStatus = typeof VulnStatus.Type

export const BugClass = Schema.Literals([
  "reentrancy",
  "access_control",
  "oracle_manipulation",
  "math_precision",
  "economic_defi",
  "invariant_violation",
  "upgradeability",
  "signature_replay",
  "erc_standards",
  "logic_error",
  "denial_of_service",
  "solana_specific",
  "other",
])
export type BugClass = typeof BugClass.Type

export const AccessLevel = Schema.Literals(["none", "user", "root", "system", "admin", "operator", "vault_owner"])
export type AccessLevel = typeof AccessLevel.Type

export const PentestPhase = Schema.Literals([
  "scope_recon",
  "static_analysis",
  "threat_modeling",
  "deep_audit",
  "poc_verification",
  "reporting",
  // Backwards compatibility with legacy names:
  "recon",
  "enumeration",
  "vuln_assess",
  "exploitation",
  "post_exploit",
])
export type PentestPhase = typeof PentestPhase.Type
export const AuditPhase = PentestPhase
export type AuditPhase = PentestPhase

export const PentestMode = Schema.Literals(["auto", "free", "guided", "deep_scan"])
export type PentestMode = typeof PentestMode.Type
export const AuditMode = PentestMode
export type AuditMode = PentestMode

export const PauseBehavior = Schema.Literals(["never", "always", "checkpoint"])
export type PauseBehavior = typeof PauseBehavior.Type

export const TaskNodeStatus = Schema.Literals(["pending", "in_progress", "done", "abandoned"])
export type TaskNodeStatus = typeof TaskNodeStatus.Type

export const ObjectiveStatus = Schema.Literals(["not_started", "in_progress", "completed", "blocked", "abandoned"])
export type ObjectiveStatus = typeof ObjectiveStatus.Type

export const ObjectivePriority = Schema.Literals(["critical", "high", "medium", "low"])
export type ObjectivePriority = typeof ObjectivePriority.Type

export const ObjectiveCategory = Schema.Literals(["audit", "smart_contract", "defi", "ctf", "bounty", "red_team", "custom"])
export type ObjectiveCategory = typeof ObjectiveCategory.Type

export const Service = Schema.Struct({
  port: Schema.Number,
  protocol: Schema.optional(Schema.String),
  service: Schema.optional(Schema.String),
  version: Schema.optional(Schema.String),
  state: Schema.optional(Schema.String),
  banner: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Service" })
export type Service = typeof Service.Type

export const VerificationStatus = Schema.Literals(["unverified", "verified", "false_positive", "poc_passed", "poc_failed"])
export type VerificationStatus = typeof VerificationStatus.Type

export const EvidenceItem = Schema.Struct({
  tool: Schema.String,
  command: Schema.optional(Schema.String),
  output: Schema.String,
  timestamp: Schema.optional(Schema.String),
  confidence: Schema.optional(Schema.Number),
  reasoning: Schema.optional(Schema.String),
  source_agent: Schema.optional(Schema.String),
  attempt_number: Schema.optional(Schema.Number),
  verification_status: Schema.optional(VerificationStatus),
}).annotate({ identifier: "Engagement.EvidenceItem" })
export type EvidenceItem = typeof EvidenceItem.Type

export const CriticReview = Schema.Struct({
  verdict: Schema.optional(Schema.Literals(["validated", "rejected", "downgraded"])),
  reason: Schema.optional(Schema.String),
  judging_gate: Schema.optional(Schema.Literals(["blocks", "allows", "irrelevant", "uncertain"])),
  reviewed_by: Schema.optional(Schema.String),
  timestamp: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.CriticReview" })
export type CriticReview = typeof CriticReview.Type

// Web3 Confidence derivation based on tool corroboration, manual review, and PoC test execution
export function deriveConfidence(vuln: {
  status?: string
  evidence_items?: ReadonlyArray<{ tool?: string; verification_status?: string }>
  proof_of_concept?: string
  critic_review?: { verdict?: string }
}): number {
  if (vuln.status === "poc_verified" || vuln.status === "exploited") return 0.99
  const items = vuln.evidence_items ?? []
  if (items.some((e) => e.verification_status === "verified" || e.verification_status === "poc_passed")) return 0.95
  if (items.length > 0 && items.every((e) => e.verification_status === "false_positive")) return 0.1
  if (vuln.critic_review?.verdict === "rejected") return 0.15
  if (vuln.critic_review?.verdict === "validated") return 0.9

  let c = 0.5 // baseline signal
  const tools = new Set(items.map((e) => e.tool).filter(Boolean))
  if (tools.size >= 2) c += 0.2 // independent tools corroborate (e.g. Slither + Math Agent)
  else if (items.length >= 2) c += 0.1 // repeated observation
  if (vuln.proof_of_concept && vuln.proof_of_concept.length > 30) c += 0.2
  if (vuln.status === "confirmed") c += 0.15
  else if (vuln.status === "lead" || vuln.status === "suspected") c -= 0.1
  return Math.round(Math.max(0.1, Math.min(0.99, c)) * 100) / 100
}

export const Vulnerability = Schema.Struct({
  id: Schema.optional(Schema.String),
  title: Schema.String,
  contract_name: Schema.optional(Schema.String),
  function_name: Schema.optional(Schema.String),
  line_start: Schema.optional(Schema.Number),
  line_end: Schema.optional(Schema.Number),
  service_port: Schema.optional(Schema.Number), // legacy support
  severity: Schema.optional(Severity),
  bug_class: Schema.optional(BugClass),
  status: Schema.optional(VulnStatus),
  confidence: Schema.optional(Schema.Number),
  description: Schema.optional(Schema.String),
  impact: Schema.optional(Schema.String),
  root_cause: Schema.optional(Schema.String),
  attack_path: Schema.optional(Schema.String),
  proof_of_concept: Schema.optional(Schema.String),
  minimal_fix: Schema.optional(Schema.String),
  evidence: Schema.optional(Schema.String),
  evidence_items: Schema.optional(Schema.Array(EvidenceItem)),
  discovered_by: Schema.optional(Schema.String),
  critic_review: Schema.optional(CriticReview),
  references: Schema.optional(Schema.Array(Schema.String)),
  swc_id: Schema.optional(Schema.String),
  cwe_id: Schema.optional(Schema.String),
  immunefi_id: Schema.optional(Schema.String),
  mitre_attack_id: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Vulnerability" })
export type Vulnerability = typeof Vulnerability.Type

// Web3 Smart Contract Models
export const StateVariable = Schema.Struct({
  name: Schema.String,
  type: Schema.String,
  visibility: Schema.optional(Schema.String),
  is_immutable: Schema.optional(Schema.Boolean),
  is_constant: Schema.optional(Schema.Boolean),
  slot: Schema.optional(Schema.Number),
  offset: Schema.optional(Schema.Number),
}).annotate({ identifier: "Engagement.StateVariable" })
export type StateVariable = typeof StateVariable.Type

export const FunctionInfo = Schema.Struct({
  name: Schema.String,
  selector: Schema.optional(Schema.String),
  visibility: Schema.optional(Schema.Literals(["public", "external", "internal", "private"])),
  mutability: Schema.optional(Schema.Literals(["pure", "view", "nonpayable", "payable"])),
  modifiers: Schema.optional(Schema.Array(Schema.String)),
  parameters: Schema.optional(Schema.Array(Schema.String)),
  returns: Schema.optional(Schema.Array(Schema.String)),
  is_payable: Schema.optional(Schema.Boolean),
  line_start: Schema.optional(Schema.Number),
  line_end: Schema.optional(Schema.Number),
}).annotate({ identifier: "Engagement.FunctionInfo" })
export type FunctionInfo = typeof FunctionInfo.Type

export const ModifierInfo = Schema.Struct({
  name: Schema.String,
  parameters: Schema.optional(Schema.Array(Schema.String)),
}).annotate({ identifier: "Engagement.ModifierInfo" })
export type ModifierInfo = typeof ModifierInfo.Type

export const EventInfo = Schema.Struct({
  name: Schema.String,
  parameters: Schema.optional(Schema.Array(Schema.String)),
  topic_hash: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.EventInfo" })
export type EventInfo = typeof EventInfo.Type

export const CustomErrorInfo = Schema.Struct({
  name: Schema.String,
  parameters: Schema.optional(Schema.Array(Schema.String)),
  selector: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.CustomErrorInfo" })
export type CustomErrorInfo = typeof CustomErrorInfo.Type

export const ProxyPattern = Schema.Literals(["none", "uups", "transparent", "diamond", "beacon", "minimal_proxy", "custom"])
export type ProxyPattern = typeof ProxyPattern.Type

export const ContractInfo = Schema.Struct({
  name: Schema.String,
  path: Schema.String,
  sloc: Schema.optional(Schema.Number),
  proxy_pattern: Schema.optional(ProxyPattern),
  compiler_version: Schema.optional(Schema.String),
  inheritance: Schema.optional(Schema.Array(Schema.String)),
  interfaces_implemented: Schema.optional(Schema.Array(Schema.String)),
  state_variables: Schema.optional(Schema.Array(StateVariable)),
  functions: Schema.optional(Schema.Array(FunctionInfo)),
  modifiers: Schema.optional(Schema.Array(ModifierInfo)),
  events: Schema.optional(Schema.Array(EventInfo)),
  custom_errors: Schema.optional(Schema.Array(CustomErrorInfo)),
  dependencies: Schema.optional(Schema.Array(Schema.String)),
  actor_permissions: Schema.optional(Schema.Record(Schema.String, Schema.Array(Schema.String))),
  verified_address: Schema.optional(Schema.String),
  chain_id: Schema.optional(Schema.Number),
  notes: Schema.optional(Schema.Array(Schema.String)),
}).annotate({ identifier: "Engagement.ContractInfo" })
export type ContractInfo = typeof ContractInfo.Type

export const Invariant = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  description: Schema.optional(Schema.String),
  target_contracts: Schema.optional(Schema.Array(Schema.String)),
  status: Schema.optional(Schema.Literals(["untested", "valid", "violated", "fuzzed"])),
  fuzz_property: Schema.optional(Schema.String),
  violation_trace: Schema.optional(Schema.String),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Invariant" })
export type Invariant = typeof Invariant.Type

export const ActorRole = Schema.Struct({
  role_name: Schema.String,
  description: Schema.optional(Schema.String),
  privileged_functions: Schema.optional(Schema.Array(Schema.String)),
  timelock_delay: Schema.optional(Schema.String),
  multisig_threshold: Schema.optional(Schema.String),
  holders: Schema.optional(Schema.Array(Schema.String)),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.ActorRole" })
export type ActorRole = typeof ActorRole.Type

export const PoCTest = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  target_vuln_id: Schema.optional(Schema.String),
  framework: Schema.optional(Schema.Literals(["foundry", "hardhat", "anchor", "custom"])),
  test_file_path: Schema.optional(Schema.String),
  command: Schema.optional(Schema.String),
  status: Schema.optional(Schema.Literals(["pending", "passed", "failed", "error"])),
  execution_trace: Schema.optional(Schema.String),
  gas_used: Schema.optional(Schema.Number),
}).annotate({ identifier: "Engagement.PoCTest" })
export type PoCTest = typeof PoCTest.Type

export const Credential = Schema.Struct({
  id: Schema.String,
  cred_type: Schema.optional(Schema.String),
  username: Schema.optional(Schema.String),
  value: Schema.optional(Schema.String),
  source: Schema.optional(Schema.String),
  valid_for: Schema.optional(Schema.Array(Schema.String)),
  confidence: Schema.optional(Schema.Number),
  domain: Schema.optional(Schema.String),
  ticket_type: Schema.optional(Schema.String),
  service_principal: Schema.optional(Schema.String),
  ticket_expiry: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Credential" })
export type Credential = typeof Credential.Type

export const Access = Schema.Struct({
  access_type: Schema.String,
  username: Schema.String,
  level: Schema.optional(AccessLevel),
  confidence: Schema.optional(Schema.Number),
  credential_id: Schema.optional(Schema.String),
  details: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Access" })
export type Access = typeof Access.Type

export const DomainInfo = Schema.Struct({
  domain: Schema.optional(Schema.String),
  is_dc: Schema.optional(Schema.Boolean),
  computer_account: Schema.optional(Schema.String),
  forest: Schema.optional(Schema.String),
  site: Schema.optional(Schema.String),
  functional_level: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.DomainInfo" })
export type DomainInfo = typeof DomainInfo.Type

export const Host = Schema.Struct({
  ip: Schema.String,
  hostname: Schema.optional(Schema.String),
  os: Schema.optional(Schema.String),
  domain_info: Schema.optional(DomainInfo),
  services: Schema.Array(Service),
  vulns: Schema.Array(Vulnerability),
  access: Schema.Array(Access),
  notes: Schema.Array(Schema.String),
}).annotate({ identifier: "Engagement.Host" })
export type Host = typeof Host.Type

export const AttackStep = Schema.Struct({
  timestamp: Schema.String,
  source: Schema.String,
  target: Schema.String,
  technique: Schema.String,
  result: Schema.String,
  success: Schema.optional(Schema.Boolean),
  mitre_attack_id: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.AttackStep" })
export type AttackStep = typeof AttackStep.Type

export const Objective = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  description: Schema.optional(Schema.String),
  status: ObjectiveStatus,
  priority: Schema.optional(ObjectivePriority),
  category: Schema.optional(ObjectiveCategory),
  target_hosts: Schema.optional(Schema.Array(Schema.String)),
  linked_vulns: Schema.optional(Schema.Array(Schema.String)),
  linked_creds: Schema.optional(Schema.Array(Schema.String)),
  flags: Schema.optional(Schema.Array(Schema.String)),
  evidence: Schema.optional(Schema.String),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Objective" })
export type Objective = typeof Objective.Type

export const Scope = Schema.Struct({
  targets: Schema.Array(Schema.String),
  excludes: Schema.Array(Schema.String),
  discovered_targets: Schema.optional(Schema.Array(Schema.String)),
  framework: Schema.optional(Schema.Literals(["foundry", "hardhat", "anchor", "truffle", "ape", "cosmwasm", "move", "raw_solidity"])),
  compiler_version: Schema.optional(Schema.String),
  target_chains: Schema.optional(Schema.Array(Schema.String)),
  external_integrations: Schema.optional(Schema.Array(Schema.String)),
  sloc_total: Schema.optional(Schema.Number),
  commit_hash: Schema.optional(Schema.String),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Scope" })
export type Scope = typeof Scope.Type
export const AuditScope = Scope
export type AuditScope = Scope

export const TaskTreeNode = Schema.Struct({
  id: Schema.String,
  parent_id: Schema.optional(Schema.String),
  description: Schema.String,
  status: Schema.optional(TaskNodeStatus),
  difficulty: Schema.optional(Schema.Number),
  target: Schema.optional(Schema.String),
  technique: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.TaskTreeNode" })
export type TaskTreeNode = typeof TaskTreeNode.Type

export const Trust = Schema.Struct({
  target_domain: Schema.String,
  trust_type: Schema.optional(Schema.String),
  trust_direction: Schema.optional(Schema.String),
  is_transitive: Schema.optional(Schema.Boolean),
}).annotate({ identifier: "Engagement.Trust" })
export type Trust = typeof Trust.Type

export const DomainState = Schema.Struct({
  domain_name: Schema.String,
  forest: Schema.optional(Schema.String),
  domain_sid: Schema.optional(Schema.String),
  trusts: Schema.optional(Schema.Array(Trust)),
  domain_controllers: Schema.optional(Schema.Array(Schema.String)),
  domain_admins: Schema.optional(Schema.Array(Schema.String)),
  gpo_names: Schema.optional(Schema.Array(Schema.String)),
  password_policy: Schema.optional(Schema.Struct({
    min_length: Schema.optional(Schema.Number),
    lockout_threshold: Schema.optional(Schema.Number),
    lockout_duration: Schema.optional(Schema.String),
    complexity_enabled: Schema.optional(Schema.Boolean),
  })),
}).annotate({ identifier: "Engagement.DomainState" })
export type DomainState = typeof DomainState.Type

export const RelationType = Schema.Literals([
  "CALLS",
  "INHERITS",
  "DELEGATES_TO",
  "MANIPULATES",
  "EXPLOITED_VIA",
  "CREDENTIAL_FROM",
  "REACHABLE_FROM",
  "TRUSTS",
  "MEMBER_OF",
  "ADMIN_OF",
  "PIVOT_TO",
  "AUTHENTICATES_TO",
  "LATERAL_MOVE",
  "CONTROLS",
])
export type RelationType = typeof RelationType.Type

export const EntityType = Schema.Literals(["contract", "function", "vuln", "invariant", "actor", "poc", "host", "credential", "service", "domain", "user", "group"])
export type EntityType = typeof EntityType.Type

export const Relationship = Schema.Struct({
  source_type: EntityType,
  source_id: Schema.String,
  rel_type: RelationType,
  target_type: EntityType,
  target_id: Schema.String,
  metadata: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Relationship" })
export type Relationship = typeof Relationship.Type

export const DecisionOutcome = Schema.Literals(["pending", "successful", "failed", "abandoned", "superseded"])
export type DecisionOutcome = typeof DecisionOutcome.Type

export const Decision = Schema.Struct({
  id: Schema.String,
  timestamp: Schema.String,
  phase: PentestPhase,
  decision: Schema.String,
  reasoning: Schema.String,
  alternatives: Schema.optional(Schema.Array(Schema.String)),
  outcome: Schema.optional(DecisionOutcome),
  outcome_notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Decision" })
export type Decision = typeof Decision.Type

export const DECISIONS_MAX_ENTRIES = 100

export const AlertSeverity = Schema.Literals(["critical", "high", "medium", "info"])
export type AlertSeverity = typeof AlertSeverity.Type

export const AlertPriority = Schema.Literals(["normal", "interrupt"])
export type AlertPriority = typeof AlertPriority.Type

export const Alert = Schema.Struct({
  id: Schema.String,
  timestamp: Schema.String,
  severity: AlertSeverity,
  priority: Schema.optional(AlertPriority),
  source_agent: Schema.optional(Schema.String),
  title: Schema.String,
  details: Schema.optional(Schema.String),
  contract_name: Schema.optional(Schema.String),
  host_ip: Schema.optional(Schema.String),
  acknowledged: Schema.optional(Schema.Boolean),
  ttl_minutes: Schema.optional(Schema.Number),
}).annotate({ identifier: "Engagement.Alert" })
export type Alert = typeof Alert.Type

export const ALERTS_MAX_ACTIVE = 50
export const ALERTS_DEFAULT_TTL_MINUTES = 60

export const SessionType = Schema.Literals(["shell", "listener", "tunnel", "socks_proxy", "port_forward", "fork_node", "fuzz_run"])
export type SessionType = typeof SessionType.Type

export const LiveSession = Schema.Struct({
  id: Schema.String,
  session_type: SessionType,
  host_ip: Schema.String,
  port: Schema.optional(Schema.Number),
  username: Schema.optional(Schema.String),
  pid: Schema.optional(Schema.Number),
  established_at: Schema.String,
  last_seen: Schema.optional(Schema.String),
  alive: Schema.optional(Schema.Boolean),
  details: Schema.optional(Schema.String),
  local_port: Schema.optional(Schema.Number),
  remote_target: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.LiveSession" })
export type LiveSession = typeof LiveSession.Type

export const ArtifactType = Schema.Literals(["exploit", "poc", "audit_report", "invariant_test", "loot", "script", "payload", "wordlist", "other"])
export type ArtifactType = typeof ArtifactType.Type

export const Artifact = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  path: Schema.String,
  type: ArtifactType,
  description: Schema.optional(Schema.String),
  contract_name: Schema.optional(Schema.String),
  host_ip: Schema.optional(Schema.String),
  created_at: Schema.String,
}).annotate({ identifier: "Engagement.Artifact" })
export type Artifact = typeof Artifact.Type
export const ARTIFACTS_MAX = 100

export const NetworkSegment = Schema.Struct({
  id: Schema.String,
  name: Schema.optional(Schema.String),
  cidr: Schema.String,
  vlan: Schema.optional(Schema.Number),
  gateway: Schema.optional(Schema.String),
  reachable_from: Schema.optional(Schema.Array(Schema.String)),
  pivot_host: Schema.optional(Schema.String),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.NetworkSegment" })
export type NetworkSegment = typeof NetworkSegment.Type

export const VectorStatus = Schema.Literals([
  "attempted", // probed, inconclusive
  "confirmed", // vulnerable
  "resolved", // definitively NOT exploitable / dead end
  "blocked", // needs a precondition not yet met
])
export type VectorStatus = typeof VectorStatus.Type

export const VectorAttempt = Schema.Struct({
  technique: Schema.String,
  outcome: Schema.Literals(["failed", "partial", "success"]),
  detail: Schema.optional(Schema.String),
  timestamp: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.VectorAttempt" })
export type VectorAttempt = typeof VectorAttempt.Type

export const VECTOR_ATTEMPT_LOG_MAX = 20

export const ResolvedVector = Schema.Struct({
  id: Schema.String,
  timestamp: Schema.String,
  target: Schema.String, // contract:function or host
  vector: Schema.String, // e.g. "read-only reentrancy on getPrice()", "ERC4626 inflation"
  status: VectorStatus,
  tested_by: Schema.optional(Schema.String),
  attempts: Schema.optional(Schema.Number),
  evidence: Schema.optional(Schema.String),
  revisit_when: Schema.optional(Schema.String),
  attempt_log: Schema.optional(Schema.Array(VectorAttempt)),
}).annotate({ identifier: "Engagement.ResolvedVector" })
export type ResolvedVector = typeof ResolvedVector.Type

export const RESOLVED_VECTORS_MAX = 300

export const GoalStatus = Schema.Literals(["active", "achieved", "blocked", "abandoned"])
export type GoalStatus = typeof GoalStatus.Type

export const Goal = Schema.Struct({
  text: Schema.String,
  status: GoalStatus,
  set_at: Schema.String,
  achieved_at: Schema.optional(Schema.String),
  evidence: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Goal" })
export type Goal = typeof Goal.Type

export const State = Schema.Struct({
  id: ID,
  name: Schema.String,
  created_at: Schema.String,
  updated_at: Schema.String,
  scope: Scope,
  contracts: Schema.optional(Schema.Record(Schema.String, ContractInfo)),
  vulns: Schema.optional(Schema.Record(Schema.String, Vulnerability)),
  invariants: Schema.optional(Schema.Record(Schema.String, Invariant)),
  actors: Schema.optional(Schema.Record(Schema.String, ActorRole)),
  pocs: Schema.optional(Schema.Record(Schema.String, PoCTest)),
  hosts: Schema.Record(Schema.String, Host),
  credentials: Schema.Record(Schema.String, Credential),
  flags: Schema.Array(Schema.String),
  attack_path: Schema.Array(AttackStep),
  task_tree: Schema.Array(TaskTreeNode),
  task_graph: Schema.optional(Schema.Record(Schema.String, Schema.Unknown)),
  objectives: Schema.optional(Schema.Record(Schema.String, Objective)),
  domain: Schema.optional(DomainState),
  relationships: Schema.optional(Schema.Array(Relationship)),
  alerts: Schema.optional(Schema.Array(Alert)),
  live_sessions: Schema.optional(Schema.Array(LiveSession)),
  network_segments: Schema.optional(Schema.Array(NetworkSegment)),
  resolved_vectors: Schema.optional(Schema.Array(ResolvedVector)),
  artifacts: Schema.optional(Schema.Array(Artifact)),
  pause_on_finding: Schema.optional(PauseBehavior),
  goal: Schema.optional(Goal),
  current_phase: PentestPhase,
  mode: PentestMode,
  notes: Schema.Array(Schema.String),
}).annotate({ identifier: "Engagement.State" })
export type State = typeof State.Type
export const AuditState = State
export type AuditState = State

export const ChangelogEntry = Schema.Struct({
  timestamp: Schema.String,
  action: Schema.String,
  entity_type: Schema.String,
  entity_id: Schema.optional(Schema.String),
  summary: Schema.String,
}).annotate({ identifier: "Engagement.ChangelogEntry" })
export type ChangelogEntry = typeof ChangelogEntry.Type

export const CHANGELOG_MAX_ENTRIES = 500

export const AgentContextSummary = Schema.Struct({
  id: Schema.String,
  agent_type: Schema.String,
  timestamp: Schema.String,
  task_description: Schema.String,
  outcome: Schema.Literals(["completed", "error"]),
  key_findings: Schema.Array(Schema.String),
  failed_attempts: Schema.Array(Schema.String),
  recommended_next: Schema.Array(Schema.String),
}).annotate({ identifier: "Engagement.AgentContextSummary" })
export type AgentContextSummary = typeof AgentContextSummary.Type

export const AGENT_CONTEXT_MAX_PER_TYPE = 10

export const WordlistToolType = Schema.Literals([
  "dir_fuzz", "brute", "vhost", "subdomain",
  "user_enum", "param_fuzz", "password_spray", "selector_fuzz",
])
export type WordlistToolType = typeof WordlistToolType.Type

export const WordlistUsage = Schema.Struct({
  host_ip: Schema.String,
  port: Schema.Number,
  tool_type: WordlistToolType,
  wordlist_path: Schema.String,
  timestamp: Schema.String,
  results_count: Schema.optional(Schema.Number),
  agent_type: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.WordlistUsage" })
export type WordlistUsage = typeof WordlistUsage.Type

export const WORDLISTS_MAX_ENTRIES = 1000

export function wordlistSummary(usages: readonly WordlistUsage[], hostIp?: string, port?: number): string {
  let filtered = [...usages]
  if (hostIp) filtered = filtered.filter((u) => u.host_ip === hostIp)
  if (port !== undefined) filtered = filtered.filter((u) => u.port === port)

  if (filtered.length === 0) return "No wordlists used yet."

  const byTarget = new Map<string, WordlistUsage[]>()
  for (const u of filtered) {
    const key = `${u.host_ip}:${u.port}`
    const list = byTarget.get(key) ?? []
    list.push(u)
    byTarget.set(key, list)
  }

  const lines: string[] = []
  for (const [target, entries] of byTarget) {
    const byTool = new Map<string, string[]>()
    for (const e of entries) {
      const list = byTool.get(e.tool_type) ?? []
      list.push(e.wordlist_path)
      byTool.set(e.tool_type, list)
    }
    lines.push(`${target}: ${[...byTool.entries()].map(([t, wl]) => `${t}=[${wl.join(",")}]`).join(" ")}`)
  }
  return lines.join("\n")
}

export function toVectorLedger(state: State, recentChanges: ChangelogEntry[] = []): string | undefined {
  const contracts = Object.entries(state.contracts ?? {})
  const hosts = Object.entries(state.hosts)
  if (contracts.length === 0 && hosts.length === 0) return undefined

  const lines: string[] = [
    "<vector-ledger> — AuditCode Strategic Board: Prioritize verified critical/high vectors; dispatch specialized auditors (math, access, economic, reentrancy); execute PoC tests; eliminate false positives with critic.",
  ]

  if (contracts.length > 0) {
    lines.push("  [In-Scope Contracts]")
    for (const [name, c] of contracts.slice(0, 20)) {
      const fnCount = c.functions?.length ?? 0
      const proxy = c.proxy_pattern && c.proxy_pattern !== "none" ? ` (Proxy:${c.proxy_pattern})` : ""
      lines.push(`  • ${name}${proxy} — ${c.path} (${c.sloc ?? "?"} SLOC, ${fnCount} funcs)`)
    }
    if (contracts.length > 20) lines.push(`    … +${contracts.length - 20} more contracts`)
  }

  // Findings summary
  const allVulns = Object.values(state.vulns ?? {})
  if (allVulns.length > 0) {
    lines.push("  [Discovered Findings / Vectors]")
    for (const v of allVulns.slice(0, 15)) {
      const poc = v.status === "poc_verified" ? " [PoC Verified ⚡]" : ""
      lines.push(`    ! [${(v.severity ?? "info").toUpperCase()}] ${v.title} (${v.contract_name ?? "contract"}:${v.function_name ?? "general"})${poc}`)
    }
    if (allVulns.length > 15) lines.push(`    … +${allVulns.length - 15} more findings (state_query vulns)`)
  }

  const dead = (state.resolved_vectors ?? []).filter((v) => v.status === "resolved")
  if (dead.length) {
    lines.push(
      `  RESOLVED — dead ends (do NOT repeat): ${dead.slice(0, 8).map((v) => `${v.target}::${v.vector}`).join(" | ")}`,
    )
  }
  lines.push("</vector-ledger>")
  return lines.join("\n")
}

export function toDiffContext(entries: ChangelogEntry[], maxEntries = 20): string | undefined {
  if (entries.length === 0) return undefined
  const recent = entries.slice(-maxEntries)
  const lines: string[] = ["Changes since last turn:"]
  for (const e of recent) {
    const ts = e.timestamp.split("T")[1]?.slice(0, 8) ?? e.timestamp
    lines.push(`  [${ts}] ${e.action} ${e.entity_type}${e.entity_id ? ` (${e.entity_id})` : ""}: ${e.summary}`)
  }
  if (entries.length > maxEntries) {
    lines.push(`  ... and ${entries.length - maxEntries} earlier changes`)
  }
  return lines.join("\n")
}

export function unvalidatedVulns(state: State): Array<{ target: string; vuln: Vulnerability }> {
  const result: Array<{ target: string; vuln: Vulnerability }> = []
  // Check top-level vulns
  for (const [id, vuln] of Object.entries(state.vulns ?? {})) {
    if (vuln.status === "suspected" || vuln.status === "lead" || (!vuln.status && (vuln.confidence === undefined || vuln.confidence < 0.8))) {
      result.push({ target: vuln.contract_name ?? id, vuln })
    }
  }
  // Check host vulns for back-compat
  for (const [ip, host] of Object.entries(state.hosts)) {
    for (const vuln of host.vulns) {
      if (vuln.status === "suspected" || (!vuln.status && (vuln.confidence === undefined || vuln.confidence < 0.8))) {
        result.push({ target: ip, vuln })
      }
    }
  }
  return result
}

export function criticHint(state: State): string | undefined {
  const unvalidated = unvalidatedVulns(state)
  if (unvalidated.length === 0) return undefined
  const lines = [`${unvalidated.length} unvalidated finding(s) — spawn "critic" subagent to 4-gate validate:`]
  for (const { target, vuln } of unvalidated.slice(0, 6)) {
    lines.push(`  • ${vuln.title} [${(vuln.severity ?? "medium").toUpperCase()}] on ${target}`)
  }
  if (unvalidated.length > 6) lines.push(`  … and ${unvalidated.length - 6} more`)
  return lines.join("\n")
}

export function activeAlerts(state: State): Alert[] {
  const now = Date.now()
  return (state.alerts ?? []).filter((a) => {
    if (a.acknowledged) return false
    const ttl = (a.ttl_minutes ?? ALERTS_DEFAULT_TTL_MINUTES) * 60 * 1000
    const created = new Date(a.timestamp).getTime()
    return now - created < ttl
  })
}

export function aliveSessions(state: State): LiveSession[] {
  return (state.live_sessions ?? []).filter((s) => s.alive !== false)
}

export function toOODAContext(state: State, recentChanges: ChangelogEntry[]): string {
  const s = summary(state)
  const lines: string[] = ["<situation-awareness>"]

  if (recentChanges.length > 0) {
    lines.push(`  Recent changes: ${recentChanges.length} mutations since last turn`)
  }

  lines.push(`  Contracts: ${s.contracts_count} in-scope | Vulns: ${s.vulnerabilities_total} (${s.critical} crit, ${s.high} high, ${s.medium} med, ${s.low} low, ${s.gas} gas, ${s.info} info) | PoCs: ${s.pocs_total}`)

  const unval = unvalidatedVulns(state)
  if (unval.length > 0) lines.push(`  Unvalidated: ${unval.length} finding(s) need critic review`)

  const alerts = activeAlerts(state)
  if (alerts.length > 0) {
    lines.push(`  ALERTS (${alerts.length}):`)
    for (const a of alerts.slice(0, 5)) {
      lines.push(`    [${a.severity.toUpperCase()}] ${a.title}${a.contract_name ? ` on ${a.contract_name}` : ""}`)
    }
  }

  lines.push("</situation-awareness>")
  return lines.join("\n")
}

export function summary(state: State) {
  const contractCount = Object.keys(state.contracts ?? {}).length
  const topVulns = Object.values(state.vulns ?? {})
  const hostVulns = Object.values(state.hosts).flatMap((h) => h.vulns)
  const allVulns = [...topVulns, ...hostVulns]
  const vulnCount = allVulns.length

  const critCount = allVulns.filter((v) => v.severity === "critical").length
  const highCount = allVulns.filter((v) => v.severity === "high").length
  const medCount = allVulns.filter((v) => v.severity === "medium").length
  const lowCount = allVulns.filter((v) => v.severity === "low").length
  const gasCount = allVulns.filter((v) => v.severity === "gas").length
  const infoCount = allVulns.filter((v) => v.severity === "info").length
  const pocCount = Object.keys(state.pocs ?? {}).length
  const invariantCount = Object.keys(state.invariants ?? {}).length
  const objectives = state.objectives ? Object.values(state.objectives) : []

  return {
    contracts_count: contractCount,
    vulnerabilities_total: vulnCount,
    critical: critCount,
    high: highCount,
    medium: medCount,
    low: lowCount,
    gas: gasCount,
    info: infoCount,
    pocs_total: pocCount,
    invariants_total: invariantCount,
    current_phase: state.current_phase,
    mode: state.mode,
    objectives_total: objectives.length,
    objectives_completed: objectives.filter((o) => o.status === "completed").length,
    objectives_in_progress: objectives.filter((o) => o.status === "in_progress").length,
    objectives_blocked: objectives.filter((o) => o.status === "blocked").length,
    // Legacy support fields:
    hosts_discovered: Object.keys(state.hosts).length,
    hosts_compromised: Object.values(state.hosts).filter((h) => h.access.length > 0).length,
    vulnerabilities: vulnCount,
    credentials: Object.keys(state.credentials).length,
    flags: state.flags.length,
    attack_steps: state.attack_path.length,
    unchecked_services: 0,
  }
}

export function decisionSummary(decisions: Decision[]): {
  total: number
  successful: number
  failed: number
  pending: number
  failedVectors: string[]
} {
  const successful = decisions.filter((d) => d.outcome === "successful").length
  const failed = decisions.filter((d) => d.outcome === "failed")
  const pending = decisions.filter((d) => !d.outcome || d.outcome === "pending").length
  return {
    total: decisions.length,
    successful,
    failed: failed.length,
    pending,
    failedVectors: failed.slice(-5).map((d) => d.decision),
  }
}

export function toResolvedVectorsContext(state: State, max = 30): string | undefined {
  const all = state.resolved_vectors ?? []
  if (all.length === 0) return undefined
  const vectors = all.filter((v) => v.status !== "confirmed")
  if (vectors.length === 0) return undefined
  const rank: Record<string, number> = { resolved: 0, blocked: 1, attempted: 2 }
  const sorted = [...vectors].sort((a, b) => (rank[a.status] ?? 9) - (rank[b.status] ?? 9))
  const shown = sorted.slice(0, max)
  const clip = (s: string) => (s.length > 90 ? s.slice(0, 90) + "…" : s)
  const lines = [
    "<resolved-vectors>",
    "Settled Smart Contract vectors — do NOT re-audit blind. RESOLVED = safe/dead-end under verified conditions. Re-open ONLY if new code paths or state interactions emerge. ATTEMPTED = try with new PoC/technique.",
  ]
  for (const v of shown) {
    const n = v.attempts && v.attempts > 1 ? ` x${v.attempts}` : ""
    const why =
      v.status === "blocked" && v.revisit_when
        ? ` (revisit: ${clip(v.revisit_when)})`
        : v.evidence
          ? ` — ${clip(v.evidence)}`
          : ""
    lines.push(`  [${v.status.toUpperCase()}] ${v.target} :: ${v.vector}${n}${why}`)
  }
  lines.push("</resolved-vectors>")
  return lines.join("\n")
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, gas: 4, info: 5 }

export function toCompactContext(state: State, maxContracts = 20, _options?: { excludeOODAFields?: boolean }): string {
  const s = summary(state)
  const data: Record<string, unknown> = {
    scope: {
      targets: state.scope.targets,
      framework: state.scope.framework,
      sloc_total: state.scope.sloc_total,
    },
    summary: s,
    phase: state.current_phase,
    mode: state.mode,
    contracts: {} as Record<string, unknown>,
    vulns: [] as Array<unknown>,
    invariants: [] as Array<unknown>,
  }

  const contracts = Object.entries(state.contracts ?? {}).slice(0, maxContracts)
  for (const [name, c] of contracts) {
    ;(data.contracts as Record<string, unknown>)[name] = {
      path: c.path,
      sloc: c.sloc,
      proxy: c.proxy_pattern,
      functions_count: c.functions?.length ?? 0,
    }
  }

  const vulns = Object.values(state.vulns ?? {}).sort(
    (a, b) => (SEVERITY_ORDER[a.severity ?? "medium"] ?? 3) - (SEVERITY_ORDER[b.severity ?? "medium"] ?? 3),
  )
  data.vulns = vulns.slice(0, 15).map((v) => ({
    id: v.id,
    title: v.title,
    severity: v.severity,
    bug_class: v.bug_class,
    status: v.status,
    contract: v.contract_name,
    function: v.function_name,
    has_poc: !!v.proof_of_concept,
  }))

  const invariants = Object.values(state.invariants ?? {})
  if (invariants.length > 0) {
    data.invariants = invariants.slice(0, 10).map((inv) => ({
      id: inv.id,
      title: inv.title,
      status: inv.status,
      targets: inv.target_contracts,
    }))
  }

  return JSON.stringify(data)
}
