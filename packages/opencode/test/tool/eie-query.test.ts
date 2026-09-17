import { describe, expect, test } from "bun:test"
import { Effect, Layer, Schema } from "effect"
import { EieQueryTool, Parameters } from "@/tool/eie-query"
import { Tool } from "@/tool/tool"
import { EIEStore } from "@auditcode/core/eie/store"
import { Truncate } from "@/tool/truncate"
import { Agent } from "@/agent/agent"

const truncateLayer = Layer.succeed(Truncate.Service, {
  cleanup: () => Effect.void,
  write: (text) => Effect.succeed("mock-path"),
  output: (text) => Effect.succeed({ content: text, truncated: false }),
  limits: () => Effect.succeed({ maxLines: 2000, maxBytes: 50 * 1024 }),
})

const agentLayer = Layer.succeed(Agent.Service, {
  get: () => Effect.succeed({} as any),
  list: () => Effect.succeed([]),
  default: () => Effect.succeed({} as any),
} as any)

const testLayer = Layer.mergeAll(EIEStore.layer, truncateLayer, agentLayer)

describe("eie_query tool", () => {
  test("parameters schema decodes valid inputs", () => {
    const valid = {
      action: "query" as const,
      category: "ACCOUNTING" as const,
      keywords: ["inflation", "donation"],
      primitives: ["ERC4626"],
    }
    const decoded = Schema.decodeUnknownSync(Parameters)(valid)
    expect(decoded.action).toBe("query")
    expect(decoded.category).toBe("ACCOUNTING")
    expect(decoded.keywords).toContain("inflation")
  })

  test("executes query action and returns ranked patterns", async () => {
    const program = Effect.gen(function* () {
      const info = yield* EieQueryTool
      const tool = yield* Tool.init(info)
      const ctx = {
        sessionID: "test-session",
        messageID: "test-msg",
        agent: "test-agent",
        callID: "call-1",
        ask: () => Effect.succeed({} as any),
      }

      const res = yield* tool.execute(
        {
          action: "query",
          category: "ACCOUNTING",
          primitives: ["ERC4626"],
        },
        ctx,
      )

      return res
    }).pipe(Effect.provide(testLayer))

    const result = await Effect.runPromise(program)
    expect(result.title).toContain("patterns matched")
    expect(result.output).toContain("PAT-ACCOUNTING-001")
    expect(result.metadata.count).toBeGreaterThanOrEqual(1)
  })

  test("executes get_pattern and returns comprehensive ontology", async () => {
    const program = Effect.gen(function* () {
      const info = yield* EieQueryTool
      const tool = yield* Tool.init(info)
      const ctx = {
        sessionID: "test-session",
        messageID: "test-msg",
        agent: "test-agent",
        callID: "call-2",
        ask: () => Effect.succeed({} as any),
      }

      const res = yield* tool.execute(
        {
          action: "get_pattern",
          pattern_id: "PAT-ACCOUNTING-001",
        },
        ctx,
      )

      return res
    }).pipe(Effect.provide(testLayer))

    const result = await Effect.runPromise(program)
    expect(result.title).toContain("PAT-ACCOUNTING-001")
    expect(result.output).toContain("Preconditions Required for Exploitability")
    expect(result.output).toContain("Known Counterexamples")
    expect(result.output).toContain("Associated Attack Templates")
    expect(result.output).toContain("Historical Precedents & Findings")
  })

  test("executes check_counterexamples and detects defenses", async () => {
    const program = Effect.gen(function* () {
      const info = yield* EieQueryTool
      const tool = yield* Tool.init(info)
      const ctx = {
        sessionID: "test-session",
        messageID: "test-msg",
        agent: "test-agent",
        callID: "call-3",
        ask: () => Effect.succeed({} as any),
      }

      const safeCode = `
        function _decimalsOffset() internal view virtual returns (uint8) {
            return 3;
        }
      `

      const vulnCode = `
        function deposit(uint256 assets) external returns (uint256 shares) {
            shares = assets * totalSupply / totalAssets();
        }
      `

      const safeRes = yield* tool.execute(
        {
          action: "check_counterexamples",
          pattern_id: "PAT-ACCOUNTING-001",
          code_snippet: safeCode,
        },
        ctx,
      )

      const vulnRes = yield* tool.execute(
        {
          action: "check_counterexamples",
          pattern_id: "PAT-ACCOUNTING-001",
          code_snippet: vulnCode,
        },
        ctx,
      )

      return { safeRes, vulnRes }
    }).pipe(Effect.provide(testLayer))

    const { safeRes, vulnRes } = await Effect.runPromise(program)
    expect(safeRes.metadata.is_likely_false_positive).toBe(true)
    expect(safeRes.output).toContain("**YES (Defended)**")
    expect(safeRes.output).toContain("CE-INFLATION-VIRTUAL-SHARES")

    expect(vulnRes.metadata.is_likely_false_positive).toBe(false)
    expect(vulnRes.output).toContain("**NO (Vulnerable Path Open)**")
  })

  test("executes match_roles and maps template semantic requirements", async () => {
    const program = Effect.gen(function* () {
      const info = yield* EieQueryTool
      const tool = yield* Tool.init(info)
      const ctx = {
        sessionID: "test-session",
        messageID: "test-msg",
        agent: "test-agent",
        callID: "call-4",
        ask: () => Effect.succeed({} as any),
      }

      const contractCode = `
        contract Vault {
            function deposit(uint256 assets) external {}
            function withdraw(uint256 shares) external {}
            function transfer(address to, uint256 amt) external {}
        }
      `

      const res = yield* tool.execute(
        {
          action: "match_roles",
          template_id: "TMPL-ERC4626-INFLATION-01",
          code_snippet: contractCode,
        },
        ctx,
      )

      return res
    }).pipe(Effect.provide(testLayer))

    const result = await Effect.runPromise(program)
    expect(result.metadata.readiness_score).toBe(1.0)
    expect(result.metadata.missing_roles.length).toBe(0)
    expect(result.output).toContain("deposit()")
    expect(result.output).toContain("withdraw()")
    expect(result.output).toContain("transfer()")
  })

  test("executes formulate_hypothesis and generates structured hypothesis card", async () => {
    const program = Effect.gen(function* () {
      const info = yield* EieQueryTool
      const tool = yield* Tool.init(info)
      const ctx = {
        sessionID: "test-session",
        messageID: "test-msg",
        agent: "test-agent",
        callID: "call-5",
        ask: () => Effect.succeed({} as any),
      }

      const res = yield* tool.execute(
        {
          action: "formulate_hypothesis",
          pattern_id: "PAT-ACCOUNTING-001",
          template_id: "TMPL-ERC4626-INFLATION-01",
          contract_name: "MockVault",
          contract_path: "src/MockVault.sol",
          observed_preconditions: {
            "PREC-EMPTY-VAULT": { observed: true, reason: "Initial deployment starts empty" },
            "PREC-DIRECT-DONATION": { observed: true, reason: "Calls asset.balanceOf(address(this))" },
            "PREC-ROUND-DOWN": { observed: true, reason: "Missing zero-shares check on mint" },
          },
          code_snippet: "function deposit(uint assets) external { shares = assets * supply / total; }",
        },
        ctx,
      )

      return res
    }).pipe(Effect.provide(testLayer))

    const result = await Effect.runPromise(program)
    expect(result.metadata.status).toBe("validated")
    expect(result.metadata.confidence).toBeGreaterThanOrEqual(0.9)
    expect(result.output).toContain("Attack Hypothesis")
    expect(result.output).toContain("VALIDATED")
  })
})
