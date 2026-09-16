import { describe, expect, test } from "bun:test"
import {
  parseModelIdentifier,
  extractSolidityCode,
  buildFallbackPoCTest,
  checkConceded,
  checkRefuted,
  checkExploitable,
  resolveFinding,
  Parameters,
} from "@/tool/debate-run"
import { Schema } from "effect"

describe("debate_run tool unit tests", () => {
  test("parseModelIdentifier extracts provider and model IDs correctly", () => {
    const claude = parseModelIdentifier("anthropic/claude-3-7-sonnet")
    expect(String(claude?.providerID)).toBe("anthropic")
    expect(String(claude?.modelID)).toBe("claude-3-7-sonnet")

    const o3 = parseModelIdentifier("openai/o3-mini")
    expect(String(o3?.providerID)).toBe("openai")
    expect(String(o3?.modelID)).toBe("o3-mini")

    expect(parseModelIdentifier("")).toBeUndefined()
    expect(parseModelIdentifier("invalidmodel")).toBeUndefined()
    expect(parseModelIdentifier(undefined)).toBeUndefined()
  })

  test("extractSolidityCode extracts code blocks from markdown", () => {
    const sample = `
Here is the exploit PoC:
\`\`\`solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitTest {
    function testAttack() public {}
}
\`\`\`
Hope this helps!
`
    const code = extractSolidityCode(sample)
    expect(code).toContain("contract ExploitTest")
    expect(code).toContain("function testAttack()")
  })

  test("extractSolidityCode handles raw contract definition fallback", () => {
    const raw = `contract DirectExploit { function attack() public {} }`
    const code = extractSolidityCode(raw)
    expect(code).toBe("contract DirectExploit { function attack() public {} }")
  })

  test("buildFallbackPoCTest generates valid Foundry test structure", () => {
    const code = buildFallbackPoCTest("Vault", "src/Vault.sol", "withdraw")
    expect(code).toContain("contract DebatePoCTest is Test")
    expect(code).toContain("Vault public target;")
    expect(code).toContain("address public attacker = address(0xbad);")
    expect(code).toContain("address public victim = address(0xa11ce);")
    expect(code).toContain("function test_DebateExploit() public")
    expect(code).toContain('abi.encodeWithSignature("withdraw()")')
  })

  test("checkConceded detects concessions accurately", () => {
    expect(checkConceded("VERDICT: CONCEDED - No guards exist")).toBe(true)
    expect(checkConceded("I concede that the finding is valid.")).toBe(true)
    expect(checkConceded("Defense accepted; line 42 reverts.")).toBe(true)
    expect(checkConceded("No defense found in source code.")).toBe(true)
    expect(checkConceded("VERDICT: REFUTED - Transaction reverts")).toBe(false)
  })

  test("checkRefuted detects refutations accurately", () => {
    expect(checkRefuted("VERDICT: REFUTED - Line 40 has require")).toBe(true)
    expect(checkRefuted("This attack is blocked by nonReentrant.")).toBe(true)
    expect(checkRefuted("Transaction reverts with InsufficientBalance.")).toBe(true)
    expect(checkRefuted("VERDICT: EXPLOITABLE - Profit realized")).toBe(false)
  })

  test("checkExploitable detects exploit assertions", () => {
    expect(checkExploitable("VERDICT: EXPLOITABLE - 100 WETH drained")).toBe(true)
    expect(checkExploitable("The exploit succeeds and leads to loss of funds.")).toBe(true)
    expect(checkRefuted("VERDICT: EXPLOITABLE - Profit realized")).toBe(false)
  })

  test("resolveFinding resolves finding 1 by index, exact ID, or search query", () => {
    const mockVulns = {
      "AC-CRITICAL-1": {
        id: "AC-CRITICAL-1",
        title: "Reentrancy in withdraw() leads to drain",
        contract_name: "Vault",
        severity: "critical",
      } as any,
      "AC-HIGH-2": {
        id: "AC-HIGH-2",
        title: "Oracle price manipulation in liquidate()",
        contract_name: "LendingPool",
        severity: "high",
      } as any,
    }

    // "finding 1" resolves index 0
    const f1 = resolveFinding("finding 1", mockVulns)
    expect(f1?.id).toBe("AC-CRITICAL-1")
    expect(f1?.vuln.contract_name).toBe("Vault")

    // "1" resolves index 0
    const num1 = resolveFinding("1", mockVulns)
    expect(num1?.id).toBe("AC-CRITICAL-1")

    // "#2" resolves index 1
    const num2 = resolveFinding("#2", mockVulns)
    expect(num2?.id).toBe("AC-HIGH-2")
    expect(num2?.vuln.contract_name).toBe("LendingPool")

    // Exact ID match
    const exact = resolveFinding("AC-CRITICAL-1", mockVulns)
    expect(exact?.id).toBe("AC-CRITICAL-1")

    // Title search
    const titleMatch = resolveFinding("price manipulation", mockVulns)
    expect(titleMatch?.id).toBe("AC-HIGH-2")

    // Non-existent finding
    expect(resolveFinding("nonexistent-id", mockVulns)).toBeUndefined()
  })

  test("Parameters schema validates optional contract_name and finding_id", () => {
    const decodedWithFinding = Schema.decodeUnknownSync(Parameters)({
      finding_id: "finding 1",
      red_model: "anthropic/claude-3-7-sonnet",
      blue_model: "openai/o3-mini",
    })
    expect(decodedWithFinding.finding_id).toBe("finding 1")
    expect(decodedWithFinding.contract_name).toBeUndefined()

    const decodedWithContract = Schema.decodeUnknownSync(Parameters)({
      contract_name: "LendingPool",
      rounds: 3,
    })
    expect(decodedWithContract.contract_name).toBe("LendingPool")
  })
})
