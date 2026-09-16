import { describe, expect, test } from "bun:test"
import {
  buildDefaultInvariants,
  generateInvariantTestCode,
  extractCounterexample,
} from "@/tool/invariant-test"
import {
  buildWeirdMatrixTest,
  getVectorGuide,
} from "@/tool/fork-simulate"

describe("invariant_test tool unit tests", () => {
  test("buildDefaultInvariants produces solvency, conservation, and zero address checks", () => {
    const invs = buildDefaultInvariants("Vault")
    expect(invs.length).toBe(3)
    expect(invs[0].id).toBe("INV-01")
    expect(invs[0].title).toContain("Solvency")
    expect(invs[0].solidity_expression).toContain("target.totalAssets()")
    expect(invs[1].id).toBe("INV-02")
    expect(invs[1].title).toContain("Conservation")
    expect(invs[2].id).toBe("INV-03")
    expect(invs[2].title).toContain("Zero Address")
  })

  test("generateInvariantTestCode creates valid Solidity with Handler and Test contract", () => {
    const invs = buildDefaultInvariants("ERC4626Vault")
    const code = generateInvariantTestCode("ERC4626Vault", "src/ERC4626Vault.sol", invs, ["deposit", "withdraw"])
    expect(code).toContain("contract ERC4626VaultHandler is Test")
    expect(code).toContain("contract ERC4626VaultInvariantsTest is StdInvariant, Test")
    expect(code).toContain("function invariant_INV_01() public view")
    expect(code).toContain("ghost_totalDeposited")
    expect(code).toContain("ghost_totalWithdrawn")
    expect(code).toContain("targetContract(address(handler))")
  })

  test("extractCounterexample correctly parses forge invariant failure output", () => {
    const mockOutput = `
Running 1 test for test/invariants/VaultInvariants.t.sol:VaultInvariantsTest
[FAIL. Reason: panic: assertion failed (0x01)]
Counterexample:
  calls: [
    VaultHandler.deposit(1000000000000000000),
    VaultHandler.withdraw(500000000000000000)
  ]
Suite result: FAILED. 0 passed; 1 failed;
`
    const extracted = extractCounterexample(mockOutput)
    expect(extracted).toContain("Counterexample:")
    expect(extracted).toContain("VaultHandler.deposit")
    expect(extracted).toContain("VaultHandler.withdraw")
  })
})

describe("fork_simulate tool unit tests", () => {
  test("getVectorGuide lists all 8 Weird ERC20 attack vectors", () => {
    const guide = getVectorGuide()
    expect(guide).toContain("Fee-on-Transfer")
    expect(guide).toContain("Missing Return Values")
    expect(guide).toContain("False Return on Failure")
    expect(guide).toContain("Rebasing Tokens")
    expect(guide).toContain("Blacklist / Pausable Tokens")
    expect(guide).toContain("ERC777 Hooks / Reentrancy")
    expect(guide).toContain("Approval Race")
    expect(guide).toContain("Extreme Decimals")
  })

  test("buildWeirdMatrixTest generates comprehensive Weird ERC20 matrix test suite", () => {
    const code = buildWeirdMatrixTest("LendingVault", "src/LendingVault.sol")
    expect(code).toContain("contract WeirdERC20MatrixTest is Test")
    expect(code).toContain("test_WeirdERC20_FeeOnTransfer")
    expect(code).toContain("test_WeirdERC20_MissingReturn")
    expect(code).toContain("test_WeirdERC20_FalseReturn")
    expect(code).toContain("test_WeirdERC20_Blacklist")
    expect(code).toContain("MockFeeOnTransferToken")
    expect(code).toContain("MockMissingReturnToken")
  })
})
