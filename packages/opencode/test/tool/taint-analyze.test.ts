import { describe, expect, test } from "bun:test"
import {
  parseStateVariables,
  extractFunctionsWithBraces,
  analyzeFunctionTaint,
  detectStorageDesync,
  generateSemanticSlice,
  Parameters,
} from "@/tool/taint-analyze"
import { Schema } from "effect"

const sampleContract = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    address public owner;
    uint256 public constant MAX_FEE = 1000;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function getExchangeRate() external view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return (totalAssets * 1e18) / totalSupply;
    }

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        totalAssets += msg.value;
        balanceOf[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 assets) external {
        require(balanceOf[msg.sender] >= assets, "Insufficient balance");
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "Transfer failed");
        totalAssets -= assets;
        balanceOf[msg.sender] -= assets;
    }

    function sweep(address recipient) external onlyOwner {
        payable(recipient).transfer(address(this).balance);
    }
}
`

describe("taint_analyze tool unit tests", () => {
  test("parseStateVariables extracts slots and types accurately", () => {
    const vars = parseStateVariables(sampleContract)
    expect(vars.length).toBe(5)

    const totalAssets = vars.find((v) => v.name === "totalAssets")
    expect(totalAssets?.type).toBe("uint256")
    expect(totalAssets?.slot).toBe(0)
    expect(totalAssets?.isConstant).toBe(false)

    const totalSupply = vars.find((v) => v.name === "totalSupply")
    expect(totalSupply?.slot).toBe(1)

    const balanceOf = vars.find((v) => v.name === "balanceOf")
    expect(balanceOf?.slot).toBe(2)

    const owner = vars.find((v) => v.name === "owner")
    expect(owner?.slot).toBe(3)

    const maxFee = vars.find((v) => v.name === "MAX_FEE")
    expect(maxFee?.isConstant).toBe(true)
    expect(maxFee?.slot).toBe(-1)
  })

  test("extractFunctionsWithBraces extracts all functions correctly", () => {
    const rawFns = extractFunctionsWithBraces(sampleContract)
    const names = rawFns.map((f) => f.name)
    expect(names).toContain("getExchangeRate")
    expect(names).toContain("deposit")
    expect(names).toContain("withdraw")
    expect(names).toContain("sweep")
  })

  test("analyzeFunctionTaint identifies sources, sanitizers, sinks, and CEI violations", () => {
    const stateVars = parseStateVariables(sampleContract)
    const rawFns = extractFunctionsWithBraces(sampleContract)

    const withdrawFn = rawFns.find((f) => f.name === "withdraw")!
    const analyzed = analyzeFunctionTaint(withdrawFn, stateVars, sampleContract)

    expect(analyzed.name).toBe("withdraw")
    expect(analyzed.sources).toContain("assets")
    expect(analyzed.sources).toContain("msg.sender")

    // Sanitizer check
    expect(analyzed.sanitizers.some((s) => s.condition.includes("balanceOf[msg.sender] >= assets"))).toBe(true)

    // Sinks check
    expect(analyzed.sinks.some((s) => s.type === "eth_transfer")).toBe(true)
    expect(analyzed.sinks.some((s) => s.type === "state_write" && s.target === "totalAssets")).toBe(true)

    // CEI Violation: call{value: assets} occurs before totalAssets -= assets
    expect(analyzed.hazards.some((h) => h.type === "cei_violation")).toBe(true)
  })

  test("detectStorageDesync detects Read-Only Reentrancy between withdraw and getExchangeRate", () => {
    const stateVars = parseStateVariables(sampleContract)
    const rawFns = extractFunctionsWithBraces(sampleContract)
    const analyzedFns = rawFns.map((f) => analyzeFunctionTaint(f, stateVars, sampleContract))

    const desyncHazards = detectStorageDesync(analyzedFns, stateVars)

    // getExchangeRate reads totalAssets (slot 0) while withdraw modifies it after external call
    const readOnlyHazard = desyncHazards.find((h) => h.type === "read_only_reentrancy")
    expect(readOnlyHazard).toBeDefined()
    expect(readOnlyHazard?.function_name).toBe("getExchangeRate")
    expect(readOnlyHazard?.affected_slots).toContain(0)
  })

  test("generateSemanticSlice formats clean markdown output", () => {
    const stateVars = parseStateVariables(sampleContract)
    const rawFns = extractFunctionsWithBraces(sampleContract)
    const analyzedFns = rawFns.map((f) => analyzeFunctionTaint(f, stateVars, sampleContract))
    const desyncHazards = detectStorageDesync(analyzedFns, stateVars)
    const allHazards = [...analyzedFns.flatMap((f) => f.hazards), ...desyncHazards]

    const result = {
      contract_name: "VulnerableVault",
      file_path: "src/Vault.sol",
      state_variables: stateVars,
      functions: analyzedFns,
      hazards: allHazards,
      summary: {
        total_functions: analyzedFns.length,
        total_slots: 4,
        total_sinks: 5,
        unguarded_sinks: 0,
        cei_violations: 1,
        read_only_reentrancy_hazards: 1,
      },
    }

    const slice = generateSemanticSlice(result)
    expect(slice).toContain("# Semantic Call-Graph & Taint Slices: `VulnerableVault`")
    expect(slice).toContain("Storage Slot Layout")
    expect(slice).toContain("getExchangeRate")
    expect(slice).toContain("withdraw")
    expect(slice).toContain("Read-Only Reentrancy Hazard")
    expect(slice).toContain("Checks-Effects-Interactions (CEI) violation")
  })

  test("Parameters schema decodes arguments correctly", () => {
    const decoded = Schema.decodeUnknownSync(Parameters)({
      contract_name: "Vault",
      file_path: "src/Vault.sol",
      focus_function: "withdraw",
    })
    expect(decoded.contract_name).toBe("Vault")
    expect(decoded.file_path).toBe("src/Vault.sol")
    expect(decoded.focus_function).toBe("withdraw")
  })
})
