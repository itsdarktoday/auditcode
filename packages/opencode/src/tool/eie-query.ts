import fs from "node:fs"
import path from "node:path"
import { Effect, Schema } from "effect"
import { EIEStore } from "@auditcode/core/eie/store"
import { EIESchema } from "@auditcode/core/eie/schema"
import DESCRIPTION from "./eie-query.txt"
import { Tool } from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.optional(
    Schema.Literals([
      "query",
      "get_pattern",
      "get_template",
      "get_counterexample",
      "check_counterexamples",
      "match_roles",
      "formulate_hypothesis",
      "load",
    ]),
  ).annotate({
    description:
      "Action to perform: 'query' (search patterns, default), 'get_pattern' (deep pattern inspect), 'get_template' (attack template), 'get_counterexample' (defense pattern), 'check_counterexamples' (false positive filter), 'match_roles' (map template roles to ABI), 'formulate_hypothesis' (attack plan with confidence), or 'load' (reload from disk).",
  }),
  pattern_id: Schema.optional(Schema.String).annotate({
    description: "Pattern ID to inspect or verify (e.g. `PAT-ACCOUNTING-001`, `PAT-REENTRANCY-RO-001`).",
  }),
  template_id: Schema.optional(Schema.String).annotate({
    description: "Attack template ID to inspect or match (e.g. `TMPL-ERC4626-INFLATION-01`).",
  }),
  counterexample_id: Schema.optional(Schema.String).annotate({
    description: "Counterexample ID to inspect (e.g. `CE-INFLATION-VIRTUAL-SHARES`).",
  }),
  category: Schema.optional(
    Schema.Literals([
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
    ]),
  ).annotate({
    description: "Vulnerability category filter.",
  }),
  keywords: Schema.optional(Schema.Array(Schema.String)).annotate({
    description: "Keywords to search across pattern names, mechanisms, and descriptions.",
  }),
  primitives: Schema.optional(Schema.Array(Schema.String)).annotate({
    description: "DeFi primitives affected (e.g. `['ERC4626', 'YieldVault', 'CurvePool']`).",
  }),
  danger_signals: Schema.optional(Schema.Array(Schema.String)).annotate({
    description: "Observed danger signals, function calls, or AST patterns (e.g. `['get_virtual_price', 'convertToShares']`).",
  }),
  contract_name: Schema.optional(Schema.String).annotate({
    description: "Target contract name (e.g. `Vault`, `LendingPool`).",
  }),
  contract_path: Schema.optional(Schema.String).annotate({
    description: "File path to the contract under review (e.g. `src/Vault.sol`).",
  }),
  code_snippet: Schema.optional(Schema.String).annotate({
    description: "Code snippet to analyze for counterexamples and precondition checks.",
  }),
  observed_preconditions: Schema.optional(
    Schema.Record(
      Schema.String,
      Schema.Struct({
        observed: Schema.Boolean,
        reason: Schema.optional(Schema.String),
      }),
    ),
  ).annotate({
    description: "Map of precondition IDs to boolean observation results with rationale.",
  }),
  custom_dir: Schema.optional(Schema.String).annotate({
    description: "Optional custom directory path to load external JSON knowledge from.",
  }),
})

function extractFunctionsFromSolidity(source: string): Array<{ name: string; mutability?: string }> {
  const functionRegex = /function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*([^{;]*)/g
  const functions: Array<{ name: string; mutability?: string }> = []
  let match: RegExpExecArray | null = null
  while ((match = functionRegex.exec(source)) !== null) {
    const name = match[1]
    const qualifiers = match[3] ?? ""
    const mutability = qualifiers.includes("payable")
      ? "payable"
      : qualifiers.includes("pure")
        ? "pure"
        : qualifiers.includes("view")
          ? "view"
          : "nonpayable"
    functions.push({ name, mutability })
  }
  return functions
}

export const EieQueryTool = Tool.define(
  "eie_query",
  Effect.gen(function* () {
    const store = yield* EIEStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (args: typeof Parameters.Type, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const action = args.action ?? "query"

      if (action === "load") {
        const counts = yield* store.loadFromDisk(args.custom_dir)
        const output = [
          `# 🧠 Exploit Intelligence Engine Knowledge Loaded`,
          "",
          `| Entity Type | Count Loaded |`,
          `|---|---|`,
          `| **Patterns** | ${counts.patternsLoaded} |`,
          `| **Attack Templates** | ${counts.templatesLoaded} |`,
          `| **Historical Findings** | ${counts.findingsLoaded} |`,
          `| **Counterexamples** | ${counts.counterexamplesLoaded} |`,
        ].join("\n")
        return {
          title: `EIE: Loaded ${counts.patternsLoaded} patterns, ${counts.counterexamplesLoaded} counterexamples`,
          metadata: counts,
          output,
        }
      }

      if (action === "get_pattern") {
        const patternId = args.pattern_id
        if (!patternId) {
          return {
            title: "EIE: Missing Pattern ID",
            metadata: { error: "Missing pattern_id" },
            output: "Error: Please specify `pattern_id` (e.g. `PAT-ACCOUNTING-001`).",
          }
        }

        const pattern = yield* store.getPattern(patternId)
        if (!pattern) {
          return {
            title: `EIE: Pattern Not Found (${patternId})`,
            metadata: { error: "Not found", patternId },
            output: `Pattern \`${patternId}\` was not found in the Exploit Intelligence Engine store.`,
          }
        }

        const templates = yield* store.getTemplatesForPattern(pattern.id)
        const counterexamples = yield* store.getCounterexamplesForPattern(pattern.id)
        const findings = yield* store.getFindingsForPattern(pattern.id)

        const output = [
          `# 🛡️ EIE Pattern: \`${pattern.id}\` — ${pattern.name}`,
          "",
          `| Property | Value |`,
          `|---|---|`,
          `| **Category** | \`${pattern.category}\` ${pattern.sub_category ? `(${pattern.sub_category})` : ""} |`,
          `| **Default Severity** | **${pattern.severity_default.toUpperCase()}** |`,
          `| **Primitives Affected** | ${pattern.primitives_affected.map((p) => `\`${p}\``).join(", ")} |`,
          `| **Root Cause Type** | \`${pattern.root_cause.type}\` |`,
          "",
          `### 🔍 Root Cause Mechanism`,
          pattern.root_cause.mechanism,
          "",
          `### 📋 Preconditions Required for Exploitability`,
          ...pattern.preconditions.map(
            (p, idx) =>
              `${idx + 1}. **\`${p.id}\`** [${p.verification_method}]${p.required ? " *(Required)*" : ""}: ${p.description}`,
          ),
          "",
          `### ⚠️ Danger Signals`,
          pattern.danger_signals.function_calls?.length
            ? `- **Function Calls**: ${pattern.danger_signals.function_calls.map((c) => `\`${c}\``).join(", ")}`
            : "",
          pattern.danger_signals.storage_access?.length
            ? `- **Storage Access**: ${pattern.danger_signals.storage_access.map((s) => `\`${s}\``).join(", ")}`
            : "",
          pattern.danger_signals.keywords?.length
            ? `- **Keywords**: ${pattern.danger_signals.keywords.map((k) => `\`${k}\``).join(", ")}`
            : "",
          "",
          `### 🛡️ Known Counterexamples (False Positive Eliminators)`,
          counterexamples.length === 0
            ? "*No counterexamples recorded for this pattern.*"
            : counterexamples
                .map(
                  (c) =>
                    `- **\`${c.id}\`**: *${c.title}*\n  Defense: ${c.mitigating_mechanism}\n  Why attack fails: ${c.why_attack_fails}`,
                )
                .join("\n"),
          "",
          `### ⚔️ Associated Attack Templates`,
          templates.length === 0
            ? "*No attack templates recorded for this pattern.*"
            : templates
                .map((t) => `- **\`${t.id}\`**: *${t.name}* (${t.attack_steps.length} attack steps)`)
                .join("\n"),
          "",
          `### 📜 Historical Precedents & Findings`,
          findings.length === 0
            ? "*No historical findings recorded for this pattern.*"
            : findings
                .map(
                  (f) =>
                    `- **\`${f.id}\`**: *${f.title}* (${f.target_protocol.name}, ${f.date}, ${f.severity.toUpperCase()}) ${f.financial_impact?.amount_usd ? `— Impact: $${f.financial_impact.amount_usd.toLocaleString()}` : ""}`,
                )
                .join("\n"),
        ]
          .filter(Boolean)
          .join("\n")

        return {
          title: `EIE: Pattern ${pattern.id} (${pattern.name})`,
          metadata: { pattern_id: pattern.id, category: pattern.category },
          output,
        }
      }

      if (action === "get_template") {
        const templateId = args.template_id
        if (!templateId) {
          return {
            title: "EIE: Missing Template ID",
            metadata: { error: "Missing template_id" },
            output: "Error: Please specify `template_id` (e.g. `TMPL-ERC4626-INFLATION-01`).",
          }
        }

        const template = yield* store.getTemplate(templateId)
        if (!template) {
          return {
            title: `EIE: Template Not Found (${templateId})`,
            metadata: { error: "Not found", templateId },
            output: `Attack template \`${templateId}\` was not found.`,
          }
        }

        const output = [
          `# ⚔️ EIE Attack Template: \`${template.id}\` — ${template.name}`,
          "",
          `**Pattern Reference**: \`${template.pattern_id}\``,
          "",
          template.description,
          "",
          `### 🎭 Semantic Role Requirements`,
          `| Role Key | Semantic Role | Expected Mutability | Candidate Function Names |`,
          `|---|---|---|---|`,
          ...Object.entries(template.semantic_role_requirements).map(
            ([key, req]) =>
              `| \`${key}\` | \`${req.role}\` | \`${req.expected_mutability ?? "any"}\` | ${req.candidate_names?.map((n) => `\`${n}\``).join(", ") ?? "heuristic"} |`,
          ),
          "",
          `### 🪜 Attack Steps Walkthrough`,
          ...template.attack_steps.map(
            (step) =>
              `${step.order}. **${step.action}**\n   - Role: \`${step.role_invoked}\`${step.parameter_rules ? `\n   - Parameter Rules: \`${step.parameter_rules}\`` : ""}${step.expected_state_delta ? `\n   - State Delta: *${step.expected_state_delta}*` : ""}`,
          ),
          "",
          template.profitability_model
            ? `### 💰 Profitability Invariant\n- Capital Formula: \`${template.profitability_model.capital_required_formula ?? "N/A"}\`\n- Proceeds Formula: \`${template.profitability_model.attacker_proceeds_formula ?? "N/A"}\`\n- Success Condition: \`${template.profitability_model.success_condition}\``
            : "",
          "",
          template.foundry_skeleton
            ? `### 🛠️ Foundry PoC Skeleton\n\`\`\`solidity\n${template.foundry_skeleton}\n\`\`\``
            : "",
        ]
          .filter(Boolean)
          .join("\n")

        return {
          title: `EIE: Template ${template.id} (${template.name})`,
          metadata: { template_id: template.id, pattern_id: template.pattern_id },
          output,
        }
      }

      if (action === "get_counterexample") {
        const ceId = args.counterexample_id
        if (!ceId) {
          return {
            title: "EIE: Missing Counterexample ID",
            metadata: { error: "Missing counterexample_id" },
            output: "Error: Please specify `counterexample_id` (e.g. `CE-INFLATION-VIRTUAL-SHARES`).",
          }
        }

        const ce = yield* store.getCounterexample(ceId)
        if (!ce) {
          return {
            title: `EIE: Counterexample Not Found (${ceId})`,
            metadata: { error: "Not found", ceId },
            output: `Counterexample \`${ceId}\` was not found.`,
          }
        }

        const output = [
          `# 🛡️ EIE Counterexample: \`${ce.id}\` — ${ce.title}`,
          "",
          `**Pattern Reference**: \`${ce.pattern_id}\``,
          "",
          `### 🎭 Apparent Vulnerability`,
          ce.apparent_vulnerability,
          "",
          `### 🔒 Mitigating Mechanism`,
          ce.mitigating_mechanism,
          "",
          `### 🛑 Why Attack Fails`,
          ce.why_attack_fails,
          "",
          `### 💻 Canonical Defense Code Example`,
          `\`\`\`solidity\n${ce.code_example}\n\`\`\``,
          "",
          ce.rejection_signal
            ? `### 🏷️ Rejection Detection Signals\n- AST Check: \`${ce.rejection_signal.ast_check ?? "none"}\`\n- Storage Check: \`${ce.rejection_signal.storage_check ?? "none"}\`\n- Revert Signature: \`${ce.rejection_signal.revert_signature ?? "none"}\``
            : "",
        ]
          .filter(Boolean)
          .join("\n")

        return {
          title: `EIE: Counterexample ${ce.id}`,
          metadata: { counterexample_id: ce.id, pattern_id: ce.pattern_id },
          output,
        }
      }

      if (action === "check_counterexamples") {
        const patternId = args.pattern_id
        if (!patternId) {
          return {
            title: "EIE: Missing Pattern ID",
            metadata: { error: "Missing pattern_id" },
            output: "Error: Please specify `pattern_id` to evaluate counterexamples against.",
          }
        }

        let code = args.code_snippet ?? ""
        if (!code && args.contract_path && fs.existsSync(args.contract_path)) {
          code = fs.readFileSync(args.contract_path, "utf-8")
        }

        const result = yield* store.checkCounterexamples(patternId, code)
        const output = [
          `# 🛡️ Counterexample Defense Analysis`,
          "",
          `| Parameter | Value |`,
          `|---|---|`,
          `| **Pattern Tested** | \`${patternId}\` |`,
          `| **False Positive Likely?** | **${result.isLikelyFalsePositive ? "YES (Defended)" : "NO (Vulnerable Path Open)"}** |`,
          `| **Evaluation Details** | ${result.reason} |`,
          "",
          ...(result.matchedCounterexamples.length > 0
            ? [
                `### ⚠️ Identified Mitigating Defenses:`,
                ...result.matchedCounterexamples.map(
                  (m) =>
                    `- **\`${m.counterexample.id}\`**: *${m.counterexample.title}*\n  - Matched Signal: \`${m.matchedRule}\`\n  - Attack Failure Mechanism: ${m.risk}`,
                ),
              ]
            : [
                `### ✅ No Counterexample Mitigations Found`,
                `The target code does not appear to implement the known defenses for \`${patternId}\`. Proceed with precondition verification and PoC formulation.`,
              ]),
        ].join("\n")

        return {
          title: `EIE Defense Check: ${result.isLikelyFalsePositive ? "False Positive Detected" : "Clear for Exploit Reasoning"}`,
          metadata: {
            pattern_id: patternId,
            is_likely_false_positive: result.isLikelyFalsePositive,
            matched_count: result.matchedCounterexamples.length,
          },
          output,
        }
      }

      if (action === "match_roles") {
        const templateId = args.template_id
        if (!templateId) {
          return {
            title: "EIE: Missing Template ID",
            metadata: { error: "Missing template_id" },
            output: "Error: Please specify `template_id` to match semantic roles.",
          }
        }

        let functions: Array<{ name: string; mutability?: string }> = []
        if (args.code_snippet) {
          functions = extractFunctionsFromSolidity(args.code_snippet)
        } else if (args.contract_path && fs.existsSync(args.contract_path)) {
          const code = fs.readFileSync(args.contract_path, "utf-8")
          functions = extractFunctionsFromSolidity(code)
        }

        const matched = yield* store.matchSemanticRoles(templateId, functions)
        if (!matched) {
          return {
            title: `EIE: Template Not Found (${templateId})`,
            metadata: { error: "Template not found" },
            output: `Template \`${templateId}\` not found.`,
          }
        }

        const output = [
          `# 🎭 Semantic Role Mapping for \`${templateId}\``,
          "",
          `**Readiness Score**: **${(matched.readinessScore * 100).toFixed(0)}%**`,
          "",
          `| Template Role Key | Semantic Role | Target Contract Function | Status |`,
          `|---|---|---|---|`,
          ...Object.entries(matched.template.semantic_role_requirements).map(([key, req]) => {
            const mapped = matched.roleMap[key]
            return `| \`${key}\` | \`${req.role}\` | ${mapped ? `\`${mapped}()\`` : "*Not Found*"} | ${mapped ? "✅ Bound" : "❌ Missing"} |`
          }),
          "",
          matched.missingRoles.length > 0
            ? `⚠️ **Missing Roles**: ${matched.missingRoles.map((r) => `\`${r}\``).join(", ")}. Exploit template cannot execute until these functions are identified or satisfied via external contracts.`
            : `🎉 **Full Alignment**: All required semantic roles mapped to target contract functions! Ready for automated Foundry PoC generation.`,
        ].join("\n")

        return {
          title: `EIE Role Match: ${(matched.readinessScore * 100).toFixed(0)}% Ready`,
          metadata: {
            template_id: templateId,
            readiness_score: matched.readinessScore,
            missing_roles: matched.missingRoles,
            role_map: matched.roleMap,
          },
          output,
        }
      }

      if (action === "formulate_hypothesis") {
        const patternId = args.pattern_id
        if (!patternId) {
          return {
            title: "EIE: Missing Pattern ID",
            metadata: { error: "Missing pattern_id" },
            output: "Error: Please specify `pattern_id` for hypothesis formulation.",
          }
        }

        let code = args.code_snippet ?? ""
        if (!code && args.contract_path && fs.existsSync(args.contract_path)) {
          code = fs.readFileSync(args.contract_path, "utf-8")
        }

        const hypothesis = yield* store.formulateHypothesis({
          patternId,
          templateId: args.template_id,
          contractName: args.contract_name,
          contractFile: args.contract_path,
          targetEvidence: [
            {
              file: args.contract_path ?? "TargetContract.sol",
              reason: "Exploit Intelligence Engine hypothesis formulation",
            },
          ],
          observedPreconditions: args.observed_preconditions,
          codeSnippet: code,
        })

        const statusBadge =
          hypothesis.status === "validated"
            ? "✅ VALIDATED (High Confidence Attack Path)"
            : hypothesis.status === "rejected"
              ? "❌ REJECTED (False Positive Defense Identified)"
              : "⏳ DRAFT (Preconditions Pending Verification)"

        const output = [
          `# 🧪 Attack Hypothesis: \`${hypothesis.id}\``,
          "",
          `| Parameter | Value |`,
          `|---|---|`,
          `| **Title** | ${hypothesis.title} |`,
          `| **Pattern ID** | \`${hypothesis.pattern_id}\` |`,
          `| **Status** | **${statusBadge}** |`,
          `| **Confidence Score** | **${(hypothesis.confidence * 100).toFixed(0)}%** |`,
          "",
          `### ⚙️ Mechanism`,
          hypothesis.mechanism,
          "",
          `### 📋 Precondition Audit Status`,
          `| Precondition ID | Description | Status | Evidence |`,
          `|---|---|---|---|`,
          ...hypothesis.precondition_status.map(
            (p) =>
              `| \`${p.condition_id}\` | ${p.description} | ${p.status === "confirmed" ? "✅ Confirmed" : p.status === "disproven" ? "❌ Disproven" : "⏳ Unconfirmed"} | ${p.evidence ?? "N/A"} |`,
          ),
          "",
          hypothesis.counterexample_risk
            ? `### ⚠️ Counterexample Defense Warning\nFinding is blocked by counterexample \`${hypothesis.counterexample_risk.counterexample_id}\`:\n*${hypothesis.counterexample_risk.risk}*`
            : "",
        ]
          .filter(Boolean)
          .join("\n")

        return {
          title: `Hypothesis: ${hypothesis.id} — ${hypothesis.status.toUpperCase()} (${(hypothesis.confidence * 100).toFixed(0)}%)`,
          metadata: hypothesis,
          output,
        }
      }

      // Default: "query"
      const results = yield* store.queryPatterns({
        category: args.category,
        keywords: args.keywords,
        primitives: args.primitives,
        dangerSignals: args.danger_signals,
      })

      if (results.length === 0) {
        return {
          title: "EIE: No Matching Patterns Found",
          metadata: { count: 0 },
          output: "No patterns matched the specified criteria. Try expanding keywords or primitives, or use `action: 'query'` with no parameters to list all known patterns.",
        }
      }

      const output = [
        `# 🧠 Exploit Intelligence Engine Query Results (${results.length} matched)`,
        "",
        `| Pattern ID | Name | Category | Severity | Score | Preconditions | Mitigations | Matched Signals |`,
        `|---|---|---|---|---|---|---|---|`,
        ...results.map(
          (r) =>
            `| \`${r.pattern.id}\` | ${r.pattern.name} | \`${r.pattern.category}\` | **${r.pattern.severity_default.toUpperCase()}** | ${r.score} | ${r.pattern.preconditions.length} | ${r.pattern.mitigations.length} | ${r.matchedSignals.length > 0 ? r.matchedSignals.map((s) => `\`${s}\``).join(", ") : "general match"} |`,
        ),
        "",
        "💡 *Tip: Call `eie_query` with `action: 'get_pattern'`, `pattern_id: '<ID>'` to view full preconditions and attack templates.*",
      ].join("\n")

        return {
          title: `EIE Query: ${results.length} patterns matched`,
          metadata: {
            count: results.length,
            top_pattern: results[0].pattern.id,
            top_score: results[0].score,
          },
          output,
        }
      }),
    }
  }),
)
