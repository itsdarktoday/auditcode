import { Effect, Schema } from "effect"
import { FSUtil } from "@auditcode/core/fs-util"
import DESCRIPTION from "./erc-validate.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  file_path: Schema.String.annotate({
    description: "Path to the contract file to validate for token standard compliance.",
  }),
  standard: Schema.Literals(["erc20", "erc721", "erc1155", "erc4626"]).annotate({
    description: "Token standard to check compliance against.",
  }),
})

export const ErcValidateTool = Tool.define(
  "erc_validate",
  Effect.gen(function* () {
    const fs = yield* FSUtil.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { file_path: string; standard: "erc20" | "erc721" | "erc1155" | "erc4626" },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const exists = yield* fs.existsSafe(params.file_path).pipe(Effect.orDie)
          if (!exists) {
            return {
              title: "File Not Found",
              metadata: {},
              output: `File not found at ${params.file_path}`,
            }
          }

          const content = yield* fs.readFileString(params.file_path).pipe(Effect.orDie)
          const warnings: string[] = []
          const compliantChecks: string[] = []

          if (params.standard === "erc20") {
            if (!content.includes("SafeERC20") && (content.includes(".transfer(") || content.includes(".transferFrom("))) {
              warnings.push("Raw IERC20.transfer / transferFrom used without SafeERC20. Non-reverting tokens (e.g. USDT) can fail silently.")
            } else {
              compliantChecks.push("Uses SafeERC20 for token transfers.")
            }

            if (content.includes("balanceOf(address(this))") && content.includes("transfer")) {
              warnings.push("Potential fee-on-transfer token vulnerability: contract assumes received amount equals transferred amount.")
            }
          }

          if (params.standard === "erc4626") {
            if (!content.includes("_decimalsOffset") && !content.includes("virtualShares") && !content.includes("virtualAssets")) {
              warnings.push("Potential ERC4626 first depositor inflation attack: no virtual offset detected in share calculation.")
            } else {
              compliantChecks.push("Implements virtual shares / offset to mitigate first-depositor share inflation.")
            }

            if (!content.includes("Math.Rounding.Floor") && !content.includes("Math.Rounding.Ceil") && !content.includes("Rounding")) {
              warnings.push("Rounding direction not explicitly specified in convertToShares / convertToAssets / previewDeposit / previewWithdraw.")
            }
          }

          if (params.standard === "erc721") {
            if (content.includes("_mint(") && !content.includes("_safeMint(")) {
              warnings.push("Uses unsafe `_mint` instead of `_safeMint`, risking NFTs permanently locked in non-receiver contracts.")
            }
            if (content.includes("_safeMint(") || content.includes("safeTransferFrom(")) {
              compliantChecks.push("Invokes onERC721Received callback (ensure reentrancy guard is present).")
            }
          }

          const lines = [
            `ERC Standard Compliance Check: ${params.file_path} (${params.standard.toUpperCase()})`,
            `Status: ${warnings.length === 0 ? "Compliant / No obvious hazards detected" : `${warnings.length} Warning(s) detected`}`,
          ]

          if (warnings.length > 0) {
            lines.push("Warnings:")
            for (const w of warnings) lines.push(`  ! ${w}`)
          }

          if (compliantChecks.length > 0) {
            lines.push("Pass Checks:")
            for (const c of compliantChecks) lines.push(`  ✓ ${c}`)
          }

          return {
            title: `ERC Check: ${params.standard.toUpperCase()}`,
            metadata: { warnings_count: warnings.length },
            output: lines.join("\n"),
          }
        }),
    }
  }),
)
