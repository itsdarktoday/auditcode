import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import DESCRIPTION from "./scope-check.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  target: Schema.String.annotate({
    description: "IP address, CIDR range, domain name, or URL to check against engagement scope",
  }),
})

export const ScopeCheckTool = Tool.define(
  "scope_check",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: { target: string }, _ctx: Tool.Context) =>
        Effect.gen(function* () {
          const state = yield* store.get()

          if (!state) {
            return {
              title: params.target,
              metadata: { in_scope: false, matched_rule: null as string | null },
              output: `no_scope_defined -- no engagement loaded. Start an engagement first.`,
            }
          }

          const scope = state.scope

          if (scope.targets.length === 0) {
            return {
              title: params.target,
              metadata: { in_scope: false, matched_rule: null as string | null },
              output: `no_scope_defined -- scope not configured, proceed with caution`,
            }
          }

          const result = ScopeMatcher.checkScope(params.target, scope)

          if (result.inScope) {
            return {
              title: params.target,
              metadata: { in_scope: true, matched_rule: result.matchedRule },
              output: `[+] ${params.target} is IN SCOPE (matched: ${result.matchedRule})`,
            }
          }

          const reason =
            result.reason === "excluded"
              ? `explicitly excluded (${result.matchedRule})`
              : `not matched by any scope rule`

          return {
            title: params.target,
            metadata: { in_scope: false, matched_rule: result.matchedRule },
            output: `[x] ${params.target} is OUT OF SCOPE -- ${reason}`,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
