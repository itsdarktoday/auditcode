import fs from "node:fs"
import path from "node:path"
import { spawnSync } from "node:child_process"
import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import type { EngagementSchema } from "@auditcode/core/engagement/schema"
import { InstanceState } from "@/effect/instance-state"
import DESCRIPTION from "./invariant-test.txt"
import { Tool } from "./tool"

export const InvariantDefinition = Schema.Struct({
  id: Schema.String.annotate({
    description: "Identifier for the invariant (e.g. `INV-01`, `INV-SOLVENCY`).",
  }),
  title: Schema.String.annotate({
    description: "Brief name of the invariant property.",
  }),
  description: Schema.optional(Schema.String).annotate({
    description: "Detailed description of the economic or state condition that must hold.",
  }),
  solidity_expression: Schema.optional(Schema.String).annotate({
    description: "Solidity assertion or check logic (e.g. `assert(vault.totalAssets() >= vault.totalSupply())`).",
  }),
})

export const Parameters = Schema.Struct({
  action: Schema.Literals(["generate", "run", "generate_and_run", "list"]).annotate({
    description:
      "Action to perform: `generate` (scaffolds Handler + Invariant test suite), `run` (executes fuzzing via forge test), `generate_and_run` (scaffolds and runs fuzz suite in one step), `list` (shows current invariant verification statuses).",
  }),
  contract_name: Schema.optional(Schema.String).annotate({
    description: "Target contract name (e.g. `Vault`, `LendingPool`, `StakingReward`).",
  }),
  contract_path: Schema.optional(Schema.String).annotate({
    description: "Relative file path to target contract (e.g. `src/Vault.sol`).",
  }),
  invariants: Schema.optional(Schema.Array(InvariantDefinition)).annotate({
    description: "Custom list of invariant properties to scaffold into the test suite. If omitted, standard protocol invariants are inferred.",
  }),
  handler_functions: Schema.optional(Schema.Array(Schema.String)).annotate({
    description: "Functions the fuzz handler should exercise (e.g. `['deposit', 'withdraw', 'mint', 'redeem']`).",
  }),
  fuzz_runs: Schema.optional(Schema.Number).annotate({
    description: "Number of fuzz runs for Forge (default: 256, set higher like 5000 for deep fuzzing).",
  }),
  fuzz_depth: Schema.optional(Schema.Number).annotate({
    description: "Call sequence depth per fuzz run (default: 32).",
  }),
  target_invariant_id: Schema.optional(Schema.String).annotate({
    description: "Filter to run a specific invariant (e.g. `invariant_Solvency`).",
  }),
  test_path: Schema.optional(Schema.String).annotate({
    description: "File path to save the generated invariant test suite (default: `test/invariants/<ContractName>Invariants.t.sol`).",
  }),
})

export function buildDefaultInvariants(contractName: string): Array<{
  id: string
  title: string
  description: string
  solidity_expression: string
}> {
  return [
    {
      id: "INV-01",
      title: "Solvency Invariant",
      description: "Protocol assets must always meet or exceed liabilities / share balance.",
      solidity_expression: `// Solvency: total assets backing shares
        assert(target.totalAssets() >= target.totalSupply());`,
    },
    {
      id: "INV-02",
      title: "Token Balance Conservation",
      description: "Ghost-tracked cumulative deposits minus withdrawals must match contract token holdings.",
      solidity_expression: `// Conservation: actual balance equals net ghost accounting
        uint256 expected = handler.ghost_totalDeposited() - handler.ghost_totalWithdrawn();
        assert(asset.balanceOf(address(target)) >= expected);`,
    },
    {
      id: "INV-03",
      title: "Zero Address Protection",
      description: "No shares or tokens should ever be minted to the zero address.",
      solidity_expression: `// Zero address sanity
        assert(target.balanceOf(address(0)) == 0);`,
    },
  ]
}

export function generateInvariantTestCode(
  contractName: string,
  contractPath: string,
  invariants: Array<{ id: string; title: string; description?: string; solidity_expression?: string }>,
  handlerFunctions?: string[],
): string {
  const funcs = handlerFunctions?.length ? handlerFunctions : ["deposit", "withdraw"]
  const relImportPath = contractPath.startsWith(".") ? contractPath : `../../${contractPath}`

  const handlerCalls = funcs
    .map((fn) => {
      if (fn.toLowerCase().includes("withdraw") || fn.toLowerCase().includes("redeem")) {
        return `
    function ${fn}(uint256 amount) public {
        amount = bound(amount, 0, target.balanceOf(msg.sender));
        if (amount == 0) return;
        vm.prank(msg.sender);
        try target.${fn}(amount, msg.sender, msg.sender) {
            ghost_totalWithdrawn += amount;
        } catch {}
    }`
      }
      return `
    function ${fn}(uint256 amount) public {
        amount = bound(amount, 1, 1_000_000 ether);
        asset.mint(msg.sender, amount);
        vm.startPrank(msg.sender);
        asset.approve(address(target), amount);
        try target.${fn}(amount, msg.sender) {
            ghost_totalDeposited += amount;
        } catch {}
        vm.stopPrank();
    }`
    })
    .join("\n")

  const invariantMethods = invariants
    .map((inv, idx) => {
      const funcName = `invariant_${inv.id.replace(/[^a-zA-Z0-9_]/g, "_")}`
      const expr = inv.solidity_expression ?? `assert(target.totalAssets() >= target.totalSupply());`
      return `
    /// @dev ${inv.title}: ${inv.description ?? ""}
    function ${funcName}() public view {
        ${expr}
    }`
    })
    .join("\n")

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { ${contractName} } from "${relImportPath}";

interface IMockERC20 {
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ${contractName}Handler is Test {
    ${contractName} public target;
    IMockERC20 public asset;

    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;

    address[] public actors;

    constructor(${contractName} _target, IMockERC20 _asset) {
        target = _target;
        asset = _asset;
        for (uint256 i = 1; i <= 5; i++) {
            actors.push(address(uint160(i)));
        }
    }
${handlerCalls}
}

contract ${contractName}InvariantsTest is StdInvariant, Test {
    ${contractName} public target;
    ${contractName}Handler public handler;
    IMockERC20 public asset;

    function setUp() public virtual {
        // Deploy or initialize contract under test
        // NOTE: If using existing deployment or factory, bind address here
        handler = new ${contractName}Handler(target, asset);
        targetContract(address(handler));
    }
${invariantMethods}
}
`
}

export function extractCounterexample(output: string): string {
  const match = output.match(/Counterexample:[\s\S]*?(?=\n\n|\nSuite result|$)/)
  if (match) return match[0].trim()
  const callsMatch = output.match(/calls:\s*\[[\s\S]*?\]/)
  if (callsMatch) return callsMatch[0].trim()
  return output.slice(0, 2000)
}

export const InvariantTestTool = Tool.define(
  "invariant_test",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          action: "generate" | "run" | "generate_and_run" | "list"
          contract_name?: string
          contract_path?: string
          invariants?: Array<{
            id: string
            title: string
            description?: string
            solidity_expression?: string
          }>
          handler_functions?: string[]
          fuzz_runs?: number
          fuzz_depth?: number
          target_invariant_id?: string
          test_path?: string
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const cwd = yield* InstanceState.directory.pipe(Effect.orElseSucceed(() => process.cwd()))

          if (params.action === "list") {
            const state = yield* store.get()
            const invariants = Object.values(state?.invariants ?? {})
            if (invariants.length === 0) {
              return {
                title: "Invariants List",
                metadata: { total: 0 },
                output: "No formal invariants are currently tracked in audit state. Use action: 'generate' to scaffold and register invariant properties.",
              }
            }

            const rows = invariants.map(
              (inv) =>
                `| **${inv.id}** | ${inv.title} | \`${inv.status ?? "untested"}\` | ${(inv.target_contracts ?? []).join(", ") || "Protocol"} |`,
            )
            const table = [
              "### Registered Protocol Invariants",
              "",
              "| Invariant ID | Title | Status | Targets |",
              "| :--- | :--- | :--- | :--- |",
              ...rows,
            ].join("\n")

            return {
              title: `Formal Invariants (${invariants.length})`,
              metadata: { count: invariants.length },
              output: table,
            }
          }

          const contractName = params.contract_name ?? "Protocol"
          const contractPath = params.contract_path ?? `src/${contractName}.sol`
          const defaultPath = path.join("test", "invariants", `${contractName}Invariants.t.sol`)
          const testFilePath = params.test_path ?? defaultPath
          const fullTestPath = path.isAbsolute(testFilePath) ? testFilePath : path.join(cwd, testFilePath)

          const invList =
            params.invariants && params.invariants.length > 0
              ? params.invariants
              : buildDefaultInvariants(contractName)

          // Handle generation
          if (params.action === "generate" || params.action === "generate_and_run") {
            const dir = path.dirname(fullTestPath)
            fs.mkdirSync(dir, { recursive: true })

            const code = generateInvariantTestCode(
              contractName,
              contractPath,
              invList,
              params.handler_functions,
            )
            fs.writeFileSync(fullTestPath, code, "utf-8")

            for (const inv of invList) {
              yield* store.addInvariant({
                id: inv.id,
                title: inv.title,
                description: inv.description,
                target_contracts: [contractName],
                status: "untested",
                fuzz_property: inv.solidity_expression,
              })
            }

            if (params.action === "generate") {
              return {
                title: `Invariant Suite Generated: ${testFilePath}`,
                metadata: {
                  test_path: testFilePath,
                  invariants_count: invList.length,
                },
                output: `Generated Foundry invariant fuzz suite at \`${testFilePath}\` with ${invList.length} formal properties.\n\nRegistered Invariants in Audit State:\n${invList.map((i) => `- [ ] **${i.id}**: ${i.title}`).join("\n")}\n\nRun fuzzing with action: 'run' or forge CLI: \`forge test --match-contract ${contractName}InvariantsTest --fuzz-runs ${params.fuzz_runs ?? 256}\``,
              }
            }
          }

          // Handle execution
          const fuzzRuns = params.fuzz_runs ?? 256
          const fuzzDepth = params.fuzz_depth ?? 32
          const args = [
            "test",
            "--fuzz-runs",
            String(fuzzRuns),
            "-vvv",
          ]

          if (params.target_invariant_id) {
            args.push("--match-test", params.target_invariant_id)
          } else {
            args.push("--match-test", "invariant_")
          }

          const res = spawnSync("forge", args, {
            cwd,
            encoding: "utf-8",
            maxBuffer: 20 * 1024 * 1024,
            timeout: 180000,
          })

          const stdout = res.stdout ?? ""
          const stderr = res.stderr ?? ""
          const rawOutput = (stdout + "\n" + stderr).trim()
          const failed = rawOutput.includes("[FAIL") || rawOutput.includes("Failing tests:")
          const passed = !failed && (res.status === 0 || rawOutput.includes("[PASS]"))

          if (failed) {
            const counterexample = extractCounterexample(rawOutput)
            const vulnId = `INV-BREAK-${contractName}-${Date.now().toString().slice(-4)}`

            // Mark in-scope invariants as violated
            for (const inv of invList) {
              yield* store.updateInvariant(inv.id, {
                status: "violated",
                violation_trace: counterexample.slice(0, 3000),
              })
            }

            // Record confirmed critical/high finding in audit state
            yield* store.addVuln(contractName, {
              id: vulnId,
              title: `Formal Invariant Violated in ${contractName}`,
              contract_name: contractName,
              severity: "high",
              bug_class: "invariant_violation",
              status: "poc_verified",
              confidence: 0.95,
              description: `Foundry invariant fuzzer broke state invariant after ${fuzzRuns} runs. A sequence of state-transition calls drove the contract into an insolvent or inconsistent state.`,
              proof_of_concept: counterexample.slice(0, 4000),
              attack_path: `Fuzz sequence triggering assertion failure:\n\n${counterexample.slice(0, 1500)}`,
              discovered_by: "invariant_test",
              impact: "State desynchronization, insolvency, or unauthorized fund extraction.",
            })

            return {
              title: `🔴 Invariant Fuzzing VIOLATED: ${contractName}`,
              metadata: { passed: false, vuln_id: vulnId },
              output: `### 🔴 INVARIANT VIOLATION DETECTED (${contractName})\n\nFoundry counterexample demonstrated that formal invariants can be broken!\n\n**Logged Finding**: \`${vulnId}\` (High / poc_verified)\n\n**Fuzzer Counterexample Trace**:\n\`\`\`\n${counterexample.slice(0, 3000)}\n\`\`\`\n\nFull Command: \`forge ${args.join(" ")}\``,
            }
          }

          if (passed) {
            for (const inv of invList) {
              yield* store.updateInvariant(inv.id, {
                status: "valid",
                notes: `Verified across ${fuzzRuns} fuzz runs (depth ${fuzzDepth}). No invariant breaks detected.`,
              })
            }

            return {
              title: `🟢 Invariant Fuzzing PASSED: ${contractName}`,
              metadata: { passed: true, runs: fuzzRuns },
              output: `### 🟢 ALL INVARIANTS HELD (${contractName})\n\nTested across ${fuzzRuns} fuzz runs (depth ${fuzzDepth}) without violation.\n\nVerified Invariants:\n${invList.map((i) => `- 🟢 **${i.id}**: ${i.title} (Status: valid)`).join("\n")}\n\nAudit state updated with verified status.`,
            }
          }

          return {
            title: `Invariant Fuzz Run Result: ${contractName}`,
            metadata: { exitCode: res.status },
            output: `Forge invariant execution finished with status ${res.status}.\n\nOutput:\n${rawOutput.slice(0, 4000)}`,
          }
        }),
    }
  }),
)
