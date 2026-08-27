import { LayerNode } from "@auditcode/core/effect/layer-node"
import path from "path"
import { InstanceState } from "@/effect/instance-state"
import { EffectBridge } from "@/effect/bridge"
import type { InstanceContext } from "@/project/instance-context"
import { Effect, Layer, Context, Schema } from "effect"
import { Config } from "@/config/config"
import { MCP } from "../mcp"
import { Skill } from "../skill"
import PROMPT_INITIALIZE from "./template/initialize.txt"
import PROMPT_REVIEW from "./template/review.txt"
import PROMPT_STATUS from "./template/audit-status.txt"
import PROMPT_CONTRACTS from "./template/audit-contracts.txt"
import PROMPT_VULNS from "./template/audit-vulns.txt"
import PROMPT_INVARIANTS from "./template/audit-invariants.txt"
import PROMPT_ACTORS from "./template/audit-actors.txt"
import PROMPT_POC from "./template/audit-poc.txt"
import PROMPT_SLITHER from "./template/audit-slither.txt"
import PROMPT_ADERYN from "./template/audit-aderyn.txt"
import PROMPT_FORGE from "./template/audit-forge.txt"
import PROMPT_PHASE from "./template/audit-phase.txt"
import PROMPT_REPORT from "./template/audit-report.txt"

import PROMPT_OBJECTIVES from "./template/audit-objectives.txt"
import PROMPT_PAUSE from "./template/audit-pause.txt"
import PROMPT_GOAL from "./template/audit-goal.txt"
import { LegacyEvent } from "@auditcode/schema/legacy-event"

type State = {
  commands: Record<string, Info>
}

export const Event = {
  Executed: LegacyEvent.CommandExecuted,
}

export const Info = Schema.Struct({
  name: Schema.String,
  description: Schema.optional(Schema.String),
  agent: Schema.optional(Schema.String),
  model: Schema.optional(Schema.String),
  source: Schema.optional(Schema.Literals(["command", "mcp", "skill"])),
  // Some command templates are lazy promises from MCP prompt resolution.
  template: Schema.Unknown,
  subtask: Schema.optional(Schema.Boolean),
  hints: Schema.Array(Schema.String),
}).annotate({ identifier: "Command" })

export type Info = Omit<Schema.Schema.Type<typeof Info>, "template"> & { template: Promise<string> | string }

export function hints(template: string) {
  const result: string[] = []
  const numbered = template.match(/\$\d+/g)
  if (numbered) {
    for (const match of [...new Set(numbered)].sort()) result.push(match)
  }
  if (template.includes("$ARGUMENTS")) result.push("$ARGUMENTS")
  return result
}

export const Default = {
  INIT: "init",
  REVIEW: "review",
    STATUS: "status",
  CONTRACTS: "contracts",
  VULNS: "vulns",
  INVARIANTS: "invariants",
  ACTORS: "actors",
  POC: "poc",
  SLITHER: "slither",
  ADERYN: "aderyn",
  FORGE: "forge",
  PHASE: "phase",
  MODE: "mode",
  REPORT: "report",
  OBJECTIVES: "objectives",
  PAUSE: "pause",
  GOAL: "goal",
} as const

export interface Interface {
  readonly get: (name: string) => Effect.Effect<Info | undefined>
  readonly list: () => Effect.Effect<Info[]>
}

export class Service extends Context.Service<Service, Interface>()("@auditcode/Command") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const config = yield* Config.Service
    const mcp = yield* MCP.Service
    const skill = yield* Skill.Service

    const init = Effect.fn("Command.state")(function* (ctx: InstanceContext) {
      const cfg = yield* config.get()
      const bridge = yield* EffectBridge.make()
      const commands: Record<string, Info> = {}

      commands[Default.INIT] = {
        name: Default.INIT,
        description: "guided AGENTS.md setup",
        source: "command",
        get template() {
          return PROMPT_INITIALIZE.replace("${path}", ctx.worktree)
        },
        hints: hints(PROMPT_INITIALIZE),
      }
      commands[Default.REVIEW] = {
        name: Default.REVIEW,
        description: "review changes [commit|branch|pr], defaults to uncommitted",
        source: "command",
        get template() {
          return PROMPT_REVIEW.replace("${path}", ctx.worktree)
        },
        subtask: true,
        hints: hints(PROMPT_REVIEW),
      }

            commands[Default.STATUS] = {
        name: Default.STATUS,
        description: "show smart contract audit status overview",
        source: "command",
        template: PROMPT_STATUS,
        hints: hints(PROMPT_STATUS),
      }
      commands[Default.CONTRACTS] = {
        name: Default.CONTRACTS,
        description: "show in-scope smart contracts table",
        source: "command",
        template: PROMPT_CONTRACTS,
        hints: hints(PROMPT_CONTRACTS),
      }
      commands[Default.VULNS] = {
        name: Default.VULNS,
        description: "show discovered vulnerabilities [severity|contract|status]",
        source: "command",
        template: PROMPT_VULNS,
        hints: hints(PROMPT_VULNS),
      }
      commands[Default.INVARIANTS] = {
        name: Default.INVARIANTS,
        description: "show protocol accounting and state invariants",
        source: "command",
        template: PROMPT_INVARIANTS,
        hints: hints(PROMPT_INVARIANTS),
      }
      commands[Default.ACTORS] = {
        name: Default.ACTORS,
        description: "show protocol roles and access control matrix",
        source: "command",
        template: PROMPT_ACTORS,
        hints: hints(PROMPT_ACTORS),
      }
      commands[Default.POC] = {
        name: Default.POC,
        description: "show registered PoC tests and verification traces",
        source: "command",
        template: PROMPT_POC,
        hints: hints(PROMPT_POC),
      }
      commands[Default.SLITHER] = {
        name: Default.SLITHER,
        description: "run Slither static analysis and ingest findings [target_path]",
        source: "command",
        template: PROMPT_SLITHER,
        hints: hints(PROMPT_SLITHER),
      }
      commands[Default.ADERYN] = {
        name: Default.ADERYN,
        description: "run Cyfrin Aderyn AST analysis and ingest findings",
        source: "command",
        template: PROMPT_ADERYN,
        hints: hints(PROMPT_ADERYN),
      }
      commands[Default.FORGE] = {
        name: Default.FORGE,
        description: "run Foundry tests or PoC verification [match_test]",
        source: "command",
        template: PROMPT_FORGE,
        hints: hints(PROMPT_FORGE),
      }
      commands[Default.PHASE] = {
        name: Default.PHASE,
        description: "show or advance audit phase [next|phase_name]",
        source: "command",
        template: PROMPT_PHASE,
        hints: hints(PROMPT_PHASE),
      }
      commands[Default.REPORT] = {
        name: Default.REPORT,
        description: "generate audit assessment report [output_path]",
        source: "command",
        template: PROMPT_REPORT,
        hints: hints(PROMPT_REPORT),
      }

      commands[Default.OBJECTIVES] = {
        name: Default.OBJECTIVES,
        description: "show or manage engagement objectives [filter|add|complete]",
        source: "command",
        template: PROMPT_OBJECTIVES,
        hints: hints(PROMPT_OBJECTIVES),
      }
      commands[Default.PAUSE] = {
        name: Default.PAUSE,
        description: "set pause behavior on findings [never|always|checkpoint]",
        source: "command",
        template: PROMPT_PAUSE,
        hints: hints(PROMPT_PAUSE),
      }

      commands[Default.GOAL] = {
        name: Default.GOAL,
        description: "set or check engagement goal [text|clear|status]",
        source: "command",
        template: PROMPT_GOAL,
        hints: hints(PROMPT_GOAL),
      }

      for (const [name, command] of Object.entries(cfg.command ?? {})) {
        commands[name] = {
          name,
          agent: command.agent,
          model: command.model,
          description: command.description,
          source: "command",
          get template() {
            return command.template
          },
          subtask: command.subtask,
          hints: hints(command.template),
        }
      }

      for (const [name, prompt] of Object.entries(yield* mcp.prompts())) {
        commands[name] = {
          name,
          source: "mcp",
          description: prompt.description,
          get template() {
            return bridge.promise(
              mcp
                .getPrompt(
                  prompt.client,
                  prompt.name,
                  prompt.arguments
                    ? Object.fromEntries(prompt.arguments.map((argument, i) => [argument.name, `$${i + 1}`]))
                    : {},
                )
                .pipe(
                  Effect.map(
                    (template) =>
                      template?.messages
                        .map((message) => (message.content.type === "text" ? message.content.text : ""))
                        .join("\n") || "",
                  ),
                ),
            )
          },
          hints: prompt.arguments?.map((_, i) => `$${i + 1}`) ?? [],
        }
      }

      for (const item of yield* skill.all()) {
        if (commands[item.name]) continue
        const dir = item.location === "<built-in>" ? undefined : path.dirname(item.location)
        commands[item.name] = {
          name: item.name,
          description: item.description,
          source: "skill",
          get template() {
            if (!dir) return item.content
            return [
              item.content,
              "",
              `Base directory for this skill: ${dir}`,
              "Relative paths in this skill (e.g., scripts/, references/) are relative to this base directory.",
            ].join("\n")
          },
          hints: [],
        }
      }

      return {
        commands,
      }
    })

    const state = yield* InstanceState.make<State>((ctx) => init(ctx))

    const get = Effect.fn("Command.get")(function* (name: string) {
      const s = yield* InstanceState.get(state)
      return s.commands[name]
    })

    const list = Effect.fn("Command.list")(function* () {
      const s = yield* InstanceState.get(state)
      return Object.values(s.commands)
    })

    return Service.of({ get, list })
  }),
)

export const node = LayerNode.make({ service: Service, layer: layer, deps: [Config.node, MCP.node, Skill.node] })

export * as Command from "."
