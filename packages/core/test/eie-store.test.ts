import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { EIEStore } from "../src/eie/store"
import { EIESchema } from "../src/eie/schema"

describe("Exploit Intelligence Engine (EIE) Store", () => {
  test("loads benchmark patterns, findings, templates, and counterexamples from disk", async () => {
    const program = Effect.gen(function* () {
      const store = yield* EIEStore.Service
      const loadResult = yield* store.loadFromDisk("/home/nishan/auditcode/data/eie")
      const patterns = yield* store.getPatterns()
      const findings = yield* store.getFindings()
      const templates = yield* store.getTemplates()
      const counterexamples = yield* store.getCounterexamples()

      return {
        loadResult,
        patterns,
        findings,
        templates,
        counterexamples,
      }
    }).pipe(Effect.provide(EIEStore.layer))

    const result = await Effect.runPromise(program)
    expect(result.patterns.length).toBeGreaterThanOrEqual(2)
    expect(result.findings.length).toBeGreaterThanOrEqual(2)
    expect(result.templates.length).toBeGreaterThanOrEqual(2)
    expect(result.counterexamples.length).toBeGreaterThanOrEqual(2)

    const pat = result.patterns.find((p) => p.id === "PAT-ACCOUNTING-001")
    expect(pat).toBeDefined()
    expect(pat?.category).toBe("ACCOUNTING")
    expect(pat?.primitives_affected).toContain("ERC4626")
  })

  test("queries patterns using multidimensional relevance scoring", async () => {
    const program = Effect.gen(function* () {
      const store = yield* EIEStore.Service
      yield* store.loadFromDisk("/home/nishan/auditcode/data/eie")

      const query1 = yield* store.queryPatterns({
        category: "ACCOUNTING",
        primitives: ["ERC4626"],
        keywords: ["inflation", "donation"],
      })

      const query2 = yield* store.queryPatterns({
        category: "REENTRANCY",
        primitives: ["CurvePool"],
        dangerSignals: ["get_virtual_price"],
      })

      return { query1, query2 }
    }).pipe(Effect.provide(EIEStore.layer))

    const result = await Effect.runPromise(program)
    expect(result.query1.length).toBeGreaterThanOrEqual(1)
    expect(result.query1[0].pattern.id).toBe("PAT-ACCOUNTING-001")
    expect(result.query1[0].score).toBeGreaterThan(50)

    expect(result.query2.length).toBeGreaterThanOrEqual(1)
    expect(result.query2[0].pattern.id).toBe("PAT-REENTRANCY-RO-001")
    expect(result.query2[0].matchedSignals).toContain("get_virtual_price")
  })

  test("evaluates preconditions accurately with observed evidence", async () => {
    const program = Effect.gen(function* () {
      const store = yield* EIEStore.Service
      yield* store.loadFromDisk("/home/nishan/auditcode/data/eie")

      const checks = yield* store.evaluatePreconditions("PAT-ACCOUNTING-001", {
        "PREC-EMPTY-VAULT": { observed: true, reason: "totalSupply is 0 at initial state" },
        "PREC-DIRECT-DONATION": { observed: true, reason: "totalAssets() returns asset.balanceOf(address(this))" },
        "PREC-ROUND-DOWN": { observed: false, reason: "require(shares > 0) prevents zero shares" },
      })

      return checks
    }).pipe(Effect.provide(EIEStore.layer))

    const checks = await Effect.runPromise(program)
    expect(checks.length).toBe(3)
    const emptyVault = checks.find((c) => c.condition_id === "PREC-EMPTY-VAULT")
    const roundDown = checks.find((c) => c.condition_id === "PREC-ROUND-DOWN")

    expect(emptyVault?.status).toBe("confirmed")
    expect(roundDown?.status).toBe("disproven")
  })

  test("detects counterexamples to eliminate false positives", async () => {
    const program = Effect.gen(function* () {
      const store = yield* EIEStore.Service
      yield* store.loadFromDisk("/home/nishan/auditcode/data/eie")

      // Target code with OpenZeppelin _decimalsOffset mitigation
      const safeCode = `
        contract MyVault is ERC4626 {
            function _decimalsOffset() internal view virtual override returns (uint8) {
                return 3;
            }
        }
      `

      // Target code without any mitigation
      const vulnerableCode = `
        contract NaiveVault {
            function deposit(uint256 assets) external returns (uint256 shares) {
                shares = assets * totalSupply / totalAssets();
            }
        }
      `

      const safeResult = yield* store.checkCounterexamples("PAT-ACCOUNTING-001", safeCode)
      const vulnResult = yield* store.checkCounterexamples("PAT-ACCOUNTING-001", vulnerableCode)

      return { safeResult, vulnResult }
    }).pipe(Effect.provide(EIEStore.layer))

    const { safeResult, vulnResult } = await Effect.runPromise(program)
    expect(safeResult.isLikelyFalsePositive).toBe(true)
    expect(safeResult.matchedCounterexamples.length).toBeGreaterThanOrEqual(1)
    expect(safeResult.matchedCounterexamples[0].counterexample.id).toBe("CE-INFLATION-VIRTUAL-SHARES")

    expect(vulnResult.isLikelyFalsePositive).toBe(false)
    expect(vulnResult.matchedCounterexamples.length).toBe(0)
  })

  test("matches semantic roles to target contract functions", async () => {
    const program = Effect.gen(function* () {
      const store = yield* EIEStore.Service
      yield* store.loadFromDisk("/home/nishan/auditcode/data/eie")

      const functions = [
        { name: "deposit", mutability: "nonpayable" },
        { name: "withdraw", mutability: "nonpayable" },
        { name: "transfer", mutability: "nonpayable" },
        { name: "balanceOf", mutability: "view" },
      ]

      const matched = yield* store.matchSemanticRoles("TMPL-ERC4626-INFLATION-01", functions)
      return matched
    }).pipe(Effect.provide(EIEStore.layer))

    const matched = await Effect.runPromise(program)
    expect(matched).toBeDefined()
    expect(matched?.roleMap["VAULT_DEPOSIT"]).toBe("deposit")
    expect(matched?.roleMap["VAULT_WITHDRAW"]).toBe("withdraw")
    expect(matched?.roleMap["VAULT_DONATE"]).toBe("transfer")
    expect(matched?.readinessScore).toBe(1.0)
  })

  test("formulates verified hypothesis and rejects false positive when defense exists", async () => {
    const program = Effect.gen(function* () {
      const store = yield* EIEStore.Service
      yield* store.loadFromDisk("/home/nishan/auditcode/data/eie")

      // Vulnerable scenario
      const vulnTarget = {
        patternId: "PAT-ACCOUNTING-001",
        templateId: "TMPL-ERC4626-INFLATION-01",
        contractName: "NaiveVault",
        contractFile: "src/NaiveVault.sol",
        targetEvidence: [{ file: "src/NaiveVault.sol", line: 42, reason: "Direct ratio calculation without offset" }],
        observedPreconditions: {
          "PREC-EMPTY-VAULT": { observed: true, reason: "Starts empty" },
          "PREC-DIRECT-DONATION": { observed: true, reason: "Uses balanceOf" },
          "PREC-ROUND-DOWN": { observed: true, reason: "No zero check" },
        },
        codeSnippet: "function deposit(uint assets) external { shares = assets * supply / total; }",
      }

      // Safe scenario with counterexample defense
      const safeTarget = {
        patternId: "PAT-ACCOUNTING-001",
        templateId: "TMPL-ERC4626-INFLATION-01",
        contractName: "SafeVault",
        contractFile: "src/SafeVault.sol",
        targetEvidence: [{ file: "src/SafeVault.sol", line: 15, reason: "Apparent inflation pattern" }],
        observedPreconditions: {
          "PREC-EMPTY-VAULT": { observed: true, reason: "Starts empty" },
        },
        codeSnippet: "function _decimalsOffset() internal view returns (uint8) { return 3; }",
      }

      const vulnHypothesis = yield* store.formulateHypothesis(vulnTarget)
      const safeHypothesis = yield* store.formulateHypothesis(safeTarget)

      return { vulnHypothesis, safeHypothesis }
    }).pipe(Effect.provide(EIEStore.layer))

    const { vulnHypothesis, safeHypothesis } = await Effect.runPromise(program)
    expect(vulnHypothesis.status).toBe("validated")
    expect(vulnHypothesis.confidence).toBeGreaterThanOrEqual(0.9)
    expect(vulnHypothesis.counterexample_risk).toBeUndefined()

    expect(safeHypothesis.status).toBe("rejected")
    expect(safeHypothesis.counterexample_risk).toBeDefined()
    expect(safeHypothesis.counterexample_risk?.counterexample_id).toBe("CE-INFLATION-VIRTUAL-SHARES")
  })
})
