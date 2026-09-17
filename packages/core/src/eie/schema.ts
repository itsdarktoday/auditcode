export * as EIESchema from "./schema"

import { Schema } from "effect"

export const Category = Schema.Literals([
  "ACCESS_CONTROL",
  "ACCOUNTING",
  "PRICE_ORACLE",
  "LIQUIDITY_VAULT",
  "REENTRANCY",
  "STATE_MACHINE",
  "SIGNATURE",
  "CROSS_CHAIN",
  "GOVERNANCE",
  "TOKEN_INTEGRATION",
  "ECONOMIC_ARBITRAGE",
])
export type Category = typeof Category.Type

export const SemanticRole = Schema.Literals([
  "FUND_IN",
  "FUND_OUT",
  "DEBT_CREATION",
  "DEBT_REDUCTION",
  "COLLATERAL_SEIZURE",
  "PRICE_ORACLE_VIEW",
  "PRICE_EXCHANGE",
  "SUPPLY_MINT",
  "SUPPLY_BURN",
  "DIRECT_DONATION",
  "STATE_SYNC",
])
export type SemanticRole = typeof SemanticRole.Type

export const VerificationMethod = Schema.Literals([
  "AST",
  "TAINT_ANALYSIS",
  "STORAGE_SLOT",
  "SYMBOLIC",
  "FOUNDRY_POC",
  "MANUAL_REVIEW",
])
export type VerificationMethod = typeof VerificationMethod.Type

export const Precondition = Schema.Struct({
  id: Schema.String,
  description: Schema.String,
  verification_method: VerificationMethod,
  required: Schema.optional(Schema.Boolean),
}).annotate({ identifier: "EIE.Precondition" })
export type Precondition = typeof Precondition.Type

export const DangerSignals = Schema.Struct({
  ast_nodes: Schema.optional(Schema.Array(Schema.String)),
  function_calls: Schema.optional(Schema.Array(Schema.String)),
  storage_access: Schema.optional(Schema.Array(Schema.String)),
  keywords: Schema.optional(Schema.Array(Schema.String)),
}).annotate({ identifier: "EIE.DangerSignals" })
export type DangerSignals = typeof DangerSignals.Type

export const Mitigation = Schema.Struct({
  name: Schema.String,
  mechanism: Schema.String,
  code_example: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.Mitigation" })
export type Mitigation = typeof Mitigation.Type

export const Pattern = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  category: Category,
  sub_category: Schema.optional(Schema.String),
  severity_default: Schema.Literals(["critical", "high", "medium", "low", "gas", "info"]),
  primitives_affected: Schema.Array(Schema.String),
  root_cause: Schema.Struct({
    type: Schema.String,
    mechanism: Schema.String,
  }),
  preconditions: Schema.Array(Precondition),
  danger_signals: DangerSignals,
  mitigations: Schema.Array(Mitigation),
  associated_templates: Schema.optional(Schema.Array(Schema.String)),
}).annotate({ identifier: "EIE.Pattern" })
export type Pattern = typeof Pattern.Type

export const FindingSource = Schema.Struct({
  type: Schema.Literals(["audit_report", "contest", "postmortem", "bug_bounty", "research"]),
  organization: Schema.optional(Schema.String),
  reference_url: Schema.String,
}).annotate({ identifier: "EIE.FindingSource" })
export type FindingSource = typeof FindingSource.Type

export const TargetProtocol = Schema.Struct({
  name: Schema.String,
  category: Schema.String,
  commit_hash: Schema.optional(Schema.String),
  repository_url: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.TargetProtocol" })
export type TargetProtocol = typeof TargetProtocol.Type

export const CodeEvidence = Schema.Struct({
  file: Schema.String,
  lines: Schema.optional(Schema.String),
  snippet: Schema.String,
  function_name: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.CodeEvidence" })
export type CodeEvidence = typeof CodeEvidence.Type

export const AttackStepWalkthrough = Schema.Struct({
  step: Schema.Number,
  action: Schema.String,
  explanation: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.AttackStepWalkthrough" })
export type AttackStepWalkthrough = typeof AttackStepWalkthrough.Type

export const FindingPoC = Schema.Struct({
  available: Schema.Boolean,
  framework: Schema.optional(Schema.Literals(["foundry", "hardhat", "ape", "native_solidity"])),
  solidity_code: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.FindingPoC" })
export type FindingPoC = typeof FindingPoC.Type

export const Finding = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  pattern_id: Schema.String,
  source: FindingSource,
  target_protocol: TargetProtocol,
  date: Schema.String,
  severity: Schema.Literals(["critical", "high", "medium", "low", "gas", "info"]),
  chain: Schema.String,
  financial_impact: Schema.optional(
    Schema.Struct({
      amount_usd: Schema.optional(Schema.Number),
      asset_stolen: Schema.optional(Schema.String),
    }),
  ),
  code_evidence: Schema.Array(CodeEvidence),
  attack_walkthrough: Schema.optional(Schema.Array(AttackStepWalkthrough)),
  poc: Schema.optional(FindingPoC),
}).annotate({ identifier: "EIE.Finding" })
export type Finding = typeof Finding.Type

export const SemanticRoleReq = Schema.Struct({
  role: SemanticRole,
  expected_mutability: Schema.optional(Schema.Literals(["payable", "nonpayable", "view", "pure"])),
  candidate_names: Schema.optional(Schema.Array(Schema.String)),
}).annotate({ identifier: "EIE.SemanticRoleReq" })
export type SemanticRoleReq = typeof SemanticRoleReq.Type

export const AttackTemplateStep = Schema.Struct({
  order: Schema.Number,
  action: Schema.String,
  role_invoked: Schema.String,
  parameter_rules: Schema.optional(Schema.String),
  expected_state_delta: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.AttackTemplateStep" })
export type AttackTemplateStep = typeof AttackTemplateStep.Type

export const ProfitabilityModel = Schema.Struct({
  capital_required_formula: Schema.optional(Schema.String),
  attacker_proceeds_formula: Schema.optional(Schema.String),
  success_condition: Schema.String,
}).annotate({ identifier: "EIE.ProfitabilityModel" })
export type ProfitabilityModel = typeof ProfitabilityModel.Type

export const AttackTemplate = Schema.Struct({
  id: Schema.String,
  pattern_id: Schema.String,
  name: Schema.String,
  description: Schema.String,
  semantic_role_requirements: Schema.Record(Schema.String, SemanticRoleReq),
  attack_steps: Schema.Array(AttackTemplateStep),
  profitability_model: Schema.optional(ProfitabilityModel),
  foundry_skeleton: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.AttackTemplate" })
export type AttackTemplate = typeof AttackTemplate.Type

export const Counterexample = Schema.Struct({
  id: Schema.String,
  pattern_id: Schema.String,
  title: Schema.String,
  apparent_vulnerability: Schema.String,
  mitigating_mechanism: Schema.String,
  code_example: Schema.String,
  why_attack_fails: Schema.String,
  rejection_signal: Schema.optional(
    Schema.Struct({
      ast_check: Schema.optional(Schema.String),
      storage_check: Schema.optional(Schema.String),
      revert_signature: Schema.optional(Schema.String),
    }),
  ),
}).annotate({ identifier: "EIE.Counterexample" })
export type Counterexample = typeof Counterexample.Type

export const PreconditionCheck = Schema.Struct({
  condition_id: Schema.String,
  description: Schema.String,
  status: Schema.Literals(["confirmed", "unconfirmed", "disproven"]),
  evidence: Schema.optional(Schema.String),
}).annotate({ identifier: "EIE.PreconditionCheck" })
export type PreconditionCheck = typeof PreconditionCheck.Type

export const HypothesisEvidence = Schema.Struct({
  file: Schema.String,
  line: Schema.optional(Schema.Number),
  reason: Schema.String,
}).annotate({ identifier: "EIE.HypothesisEvidence" })
export type HypothesisEvidence = typeof HypothesisEvidence.Type

export const Hypothesis = Schema.Struct({
  id: Schema.String,
  pattern_id: Schema.String,
  template_id: Schema.optional(Schema.String),
  title: Schema.String,
  mechanism: Schema.String,
  target_evidence: Schema.Array(HypothesisEvidence),
  precondition_status: Schema.Array(PreconditionCheck),
  counterexample_risk: Schema.optional(
    Schema.Struct({
      counterexample_id: Schema.String,
      risk: Schema.String,
    }),
  ),
  confidence: Schema.Number,
  status: Schema.Literals(["draft", "validated", "rejected", "tested"]),
}).annotate({ identifier: "EIE.Hypothesis" })
export type Hypothesis = typeof Hypothesis.Type
