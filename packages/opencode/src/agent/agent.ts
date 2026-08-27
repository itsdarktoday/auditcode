import { LayerNode } from "@auditcode/core/effect/layer-node"
import { PermissionV1 } from "@auditcode/core/v1/permission"
import { Config } from "@/config/config"
import { serviceUse } from "@auditcode/core/effect/service-use"
import { Provider } from "@/provider/provider"

import { generateObject, streamObject, type ModelMessage } from "ai"
import { Truncate } from "@/tool/truncate"
import { Auth } from "../auth"
import { ProviderTransform } from "@/provider/transform"

import PROMPT_GENERATE from "./generate.txt"
import PROMPT_COMPACTION from "./prompt/compaction.txt"
import PROMPT_AUDIT from "../session/prompt/audit.txt"
import PROMPT_RECON from "../session/prompt/recon.txt"
import PROMPT_STATIC_ANALYST from "../session/prompt/static-analyst.txt"
import PROMPT_MATH_PRECISION from "../session/prompt/math-precision.txt"
import PROMPT_ACCESS_CONTROL from "../session/prompt/access-control.txt"
import PROMPT_ECONOMIC_SECURITY from "../session/prompt/economic-security.txt"
import PROMPT_REENTRANCY from "../session/prompt/reentrancy.txt"
import PROMPT_INVARIANT from "../session/prompt/invariant.txt"
import PROMPT_PERIPHERY from "../session/prompt/periphery.txt"
import PROMPT_BOUNDARY from "../session/prompt/boundary.txt"
import PROMPT_POC_DEV from "../session/prompt/poc-dev.txt"
import PROMPT_SOLANA from "../session/prompt/solana.txt"
import PROMPT_CRITIC from "../session/prompt/critic.txt"
import PROMPT_REPORTER from "../session/prompt/reporter.txt"
import PROMPT_PENTEST from "../session/prompt/audit.txt"

import PROMPT_SUMMARY from "./prompt/summary.txt"
import PROMPT_TITLE from "./prompt/title.txt"
import { Permission } from "@/permission"
import { mergeDeep, pipe, sortBy, values } from "remeda"
import { Global } from "@auditcode/core/global"
import path from "path"
import { Plugin } from "@/plugin"
import { Skill } from "../skill"
import { Effect, Context, Layer, Schema } from "effect"
import { InstanceState } from "@/effect/instance-state"
import * as Option from "effect/Option"
import * as OtelTracer from "@effect/opentelemetry/Tracer"
import { AbsolutePath, type DeepMutable } from "@auditcode/core/schema"
import { ProviderV2 } from "@auditcode/core/provider"
import { ModelV2 } from "@auditcode/core/model"
import { LocationServiceMap, locationServiceMapLayer } from "@auditcode/core/location-services"
import { Reference } from "@auditcode/core/reference"
import { Location } from "@auditcode/core/location"
import { PluginV2 } from "@auditcode/core/plugin"

export const Info = Schema.Struct({
  name: Schema.String,
  description: Schema.optional(Schema.String),
  mode: Schema.Literals(["subagent", "primary", "all"]),
  native: Schema.optional(Schema.Boolean),
  hidden: Schema.optional(Schema.Boolean),
  topP: Schema.optional(Schema.Finite),
  temperature: Schema.optional(Schema.Finite),
  color: Schema.optional(Schema.String),
  permission: PermissionV1.Ruleset,
  model: Schema.optional(
    Schema.Struct({
      modelID: ModelV2.ID,
      providerID: ProviderV2.ID,
    }),
  ),
  variant: Schema.optional(Schema.String),
  prompt: Schema.optional(Schema.String),
  options: Schema.Record(Schema.String, Schema.Unknown),
  steps: Schema.optional(Schema.Finite),
}).annotate({ identifier: "Agent" })
export type Info = DeepMutable<Schema.Schema.Type<typeof Info>>

const GeneratedAgent = Schema.Struct({
  identifier: Schema.String,
  whenToUse: Schema.String,
  systemPrompt: Schema.String,
})

export interface Interface {
  readonly get: (agent: string) => Effect.Effect<Info>
  readonly list: () => Effect.Effect<Info[]>
  readonly defaultInfo: () => Effect.Effect<Info>
  readonly defaultAgent: () => Effect.Effect<string>
  readonly generate: (input: {
    description: string
    model?: { providerID: ProviderV2.ID; modelID: ModelV2.ID }
  }) => Effect.Effect<
    {
      identifier: string
      whenToUse: string
      systemPrompt: string
    },
    Provider.DefaultModelError
  >
}

type State = Omit<Interface, "generate">

export class Service extends Context.Service<Service, Interface>()("@auditcode/Agent") {}

export const use = serviceUse(Service)

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const config = yield* Config.Service
    const auth = yield* Auth.Service
    const plugin = yield* Plugin.Service
    const skill = yield* Skill.Service
    const provider = yield* Provider.Service
    const locations = yield* LocationServiceMap.Service

    const state = yield* InstanceState.make<State>(
      Effect.fn("Agent.state")(function* (ctx) {
        const cfg = yield* config.get()
        const skillDirs = yield* skill.dirs()
        const referenceDirs = Object.keys(cfg.references ?? cfg.reference ?? {}).length
          ? yield* Effect.gen(function* () {
              yield* (yield* PluginV2.Service).wait(PluginV2.ID.make("core/config-reference"))
              return (yield* (yield* Reference.Service).list()).map((reference) => reference.path)
            }).pipe(Effect.provide(locations.get(Location.Ref.make({ directory: AbsolutePath.make(ctx.directory) }))))
          : []
        const whitelistedDirs = [
          Truncate.GLOB,
          path.join(Global.Path.tmp, "*"),
          ...skillDirs.map((dir) => path.join(dir, "*")),
          ...referenceDirs.map((dir) => path.join(dir, "*")),
        ]
        const readonlyExternalDirectory = {
          "*": "ask",
          ...Object.fromEntries(whitelistedDirs.map((dir) => [dir, "allow"])),
        } satisfies Record<string, "allow" | "ask" | "deny">

        const defaults = Permission.fromConfig({
          "*": "allow",
          doom_loop: "ask",
          external_directory: {
            "*": "ask",
            ...Object.fromEntries(whitelistedDirs.map((dir) => [dir, "allow"])),
          },
          question: "deny",
          plan_enter: "deny",
          plan_exit: "deny",
          // mirrors github.com/github/gitignore Node.gitignore pattern for .env files
          read: {
            "*": "allow",
            "*.env": "ask",
            "*.env.*": "ask",
            "*.env.example": "allow",
          },
        })

        const user = Permission.fromConfig(cfg.permission ?? {})

        const agents: Record<string, Info> = {
                    audit: {
            name: "audit",
            description: "Primary Smart Contract Security Lead Auditor and Coordinator. Plans audit phases, dispatches specialist agents, verifies findings, and maintains audit state.",
            steps: 300,
            options: {},
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                question: "allow",
                plan_enter: "allow",
                state_query: "allow",
                state_update: "allow",
                slither_parse: "allow",
                aderyn_parse: "allow",
                foundry_test: "allow",
                contract_inspect: "allow",
                storage_layout: "allow",
                signature_lookup: "allow",
                erc_validate: "allow",
                scope_check: "allow",
                phase_control: "allow",
                report_gen: "allow",
                task_graph: "allow",
              }),
              user,
            ),
            mode: "primary",
            native: true,
          },
          recon: {
            name: "recon",
            description: "Scope & Architecture Reconnaissance agent. Scans repository, detects frameworks, maps contract topology, inheritance, and entry points.",
            options: {},
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                question: "allow",
                plan_exit: "allow",
                bash: "allow",
                read: "allow",
                write: "allow",
                edit: "allow",
                grep: "allow",
                glob: "allow",
                webfetch: "allow",
                websearch: "allow",
                state_query: "allow",
                state_update: "allow",
                contract_inspect: "allow",
                scope_check: "allow",
                phase_control: "allow",
              }),
              user,
            ),
            prompt: PROMPT_RECON,
            steps: 300,
            mode: "primary",
            native: true,
          },
          static_analyst: {
            name: "static_analyst",
            steps: 100,
            description: "Static analysis and automated tooling specialist (Slither, Aderyn, Solhint, Semgrep).",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                edit: { "*": "deny" },
                state_query: "allow",
                state_update: "allow",
                slither_parse: "allow",
                aderyn_parse: "allow",
                contract_inspect: "allow",
                scope_check: "allow",
              }),
              user,
            ),
            prompt: PROMPT_STATIC_ANALYST,
            options: {},
            mode: "subagent",
            native: true,
          },
          math_precision: {
            name: "math_precision",
            steps: 150,
            description: "Arithmetic, fixed-point math, rounding direction, decimal scaling, and ERC4626 vault inflation specialist.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
                erc_validate: "allow",
              }),
              user,
            ),
            prompt: PROMPT_MATH_PRECISION,
            options: {},
            mode: "subagent",
            native: true,
          },
          access_control: {
            name: "access_control",
            steps: 150,
            description: "Authorization, modifier checks, initializers, signature verification/malleability, and governance specialist.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
                signature_lookup: "allow",
              }),
              user,
            ),
            prompt: PROMPT_ACCESS_CONTROL,
            options: {},
            mode: "subagent",
            native: true,
          },
          economic_security: {
            name: "economic_security",
            steps: 200,
            description: "DeFi mechanics, flash loans, spot-price AMM oracles, sandwich/MEV, liquidations, and tokenomics specialist.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
              }),
              user,
            ),
            prompt: PROMPT_ECONOMIC_SECURITY,
            options: {},
            mode: "subagent",
            native: true,
          },
          reentrancy: {
            name: "reentrancy",
            steps: 150,
            description: "Read-only reentrancy, cross-contract/cross-function reentrancy, ERC777/1155 callbacks, and control flow specialist.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
              }),
              user,
            ),
            prompt: PROMPT_REENTRANCY,
            options: {},
            mode: "subagent",
            native: true,
          },
          invariant_agent: {
            name: "invariant_agent",
            steps: 150,
            description: "Protocol solvency invariants, accounting invariants, state machine, and formal property fuzzing specialist.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
              }),
              user,
            ),
            prompt: PROMPT_INVARIANT,
            options: {},
            mode: "subagent",
            native: true,
          },
          periphery_agent: {
            name: "periphery_agent",
            steps: 150,
            description: "Token standards (ERC20/721/1155/4626), weird ERC20 quirks (USDT, fee-on-transfer, rebasing), and permit specialist.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
                erc_validate: "allow",
              }),
              user,
            ),
            prompt: PROMPT_PERIPHERY,
            options: {},
            mode: "subagent",
            native: true,
          },
          boundary_agent: {
            name: "boundary_agent",
            steps: 150,
            description: "Zero amounts, max bounds, off-by-one, boundary edge cases, and empty pool state specialist.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
              }),
              user,
            ),
            prompt: PROMPT_BOUNDARY,
            options: {},
            mode: "subagent",
            native: true,
          },
          poc_dev: {
            name: "poc_dev",
            steps: 250,
            description: "Proof-of-Concept Developer. Writes and executes runnable Foundry/Forge test cases to prove vulnerabilities.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                edit: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                foundry_test: "allow",
                scope_check: "allow",
              }),
              user,
            ),
            prompt: PROMPT_POC_DEV,
            options: {},
            mode: "subagent",
            native: true,
          },
          solana_analyst: {
            name: "solana_analyst",
            steps: 200,
            description: "Solana & Anchor program security specialist. Missing signers, PDA seed collisions, duplicate accounts, and integer overflow.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                bash: "allow",
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                state_update: "allow",
                scope_check: "allow",
              }),
              user,
            ),
            prompt: PROMPT_SOLANA,
            options: {},
            mode: "subagent",
            native: true,
          },
          critic: {
            name: "critic",
            steps: 80,
            description: "Finding validator and 4-gate quality reviewer. Validates reachability, eliminates false positives, and rates severity. Read-only.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                state_query: "allow",
                state_update: "allow",
                read: "allow",
                grep: "allow",
                glob: "allow",
                bash: "deny",
                write: "deny",
                edit: "deny",
              }),
              user,
            ),
            prompt: PROMPT_CRITIC,
            options: {},
            mode: "subagent",
            native: true,
          },
          reporter: {
            name: "reporter",
            steps: 100,
            description: "Audit Report Synthesis Specialist. Formats comprehensive markdown/JSON audit reports.",
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                read: "allow",
                write: "allow",
                grep: "allow",
                glob: "allow",
                state_query: "allow",
                report_gen: "allow",
                bash: "deny",
                edit: "deny",
              }),
              user,
            ),
            prompt: PROMPT_REPORTER,
            options: {},
            mode: "subagent",
            native: true,
          },
          pentest: {
            name: "pentest",
            description: "Lead Auditor alias.",
            steps: 300,
            options: {},
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                question: "allow",
                plan_enter: "allow",
                state_query: "allow",
                state_update: "allow",
                report_gen: "allow",
                task_graph: "allow",
              }),
              user,
            ),
            mode: "primary",
            native: true,
          },

          compaction: {
            name: "compaction",
            mode: "primary",
            native: true,
            hidden: true,
            prompt: PROMPT_COMPACTION,
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                "*": "deny",
              }),
              user,
            ),
            options: {},
          },
          title: {
            name: "title",
            mode: "primary",
            options: {},
            native: true,
            hidden: true,
            temperature: 0.5,
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                "*": "deny",
              }),
              user,
            ),
            prompt: PROMPT_TITLE,
          },
          summary: {
            name: "summary",
            mode: "primary",
            options: {},
            native: true,
            hidden: true,
            permission: Permission.merge(
              defaults,
              Permission.fromConfig({
                "*": "deny",
              }),
              user,
            ),
            prompt: PROMPT_SUMMARY,
          },
        }

        for (const [key, value] of Object.entries(cfg.agent ?? {})) {
          if (value.disable) {
            delete agents[key]
            continue
          }
          let item = agents[key]
          if (!item)
            item = agents[key] = {
              name: key,
              mode: "all",
              permission: Permission.merge(defaults, user),
              options: {},
              native: false,
            }
          if (value.model) item.model = Provider.parseModel(value.model)
          item.variant = value.variant ?? item.variant
          item.prompt = value.prompt ?? item.prompt
          item.description = value.description ?? item.description
          item.temperature = value.temperature ?? item.temperature
          item.topP = value.top_p ?? item.topP
          item.mode = value.mode ?? item.mode
          item.color = value.color ?? item.color
          item.hidden = value.hidden ?? item.hidden
          item.name = value.name ?? item.name
          item.steps = value.steps ?? item.steps
          item.options = mergeDeep(item.options, value.options ?? {})
          item.permission = Permission.merge(item.permission, Permission.fromConfig(value.permission ?? {}))
        }

        // Ensure Truncate.GLOB is allowed unless explicitly configured
        for (const name in agents) {
          const agent = agents[name]
          const explicit = agent.permission.some((r) => {
            if (r.permission !== "external_directory") return false
            if (r.action !== "deny") return false
            return r.pattern === Truncate.GLOB
          })
          if (explicit) continue

          agents[name].permission = Permission.merge(
            agents[name].permission,
            Permission.fromConfig({ external_directory: { [Truncate.GLOB]: "allow" } }),
          )
        }

        const get = Effect.fnUntraced(function* (agent: string) {
          if (agent === "build") return agents["audit"];
          return agents[agent]
        })

        const list = Effect.fnUntraced(function* () {
          const cfg = yield* config.get()
          return pipe(
            agents,
            values(),
            sortBy(
              [(x) => (cfg.default_agent ? x.name === cfg.default_agent : x.name === "audit"), "desc"],
              [(x) => x.name, "asc"],
            ),
          )
        })

        const defaultInfo = Effect.fnUntraced(function* () {
          const c = yield* config.get()
          if (c.default_agent) {
            const agent = agents[c.default_agent]
            if (!agent) throw new Error(`default agent "${c.default_agent}" not found`)
            if (agent.mode === "subagent") throw new Error(`default agent "${c.default_agent}" is a subagent`)
            if (agent.hidden === true) throw new Error(`default agent "${c.default_agent}" is hidden`)
            return agent
          }
          const visible = Object.values(agents).find((a) => a.mode !== "subagent" && a.hidden !== true)
          if (!visible) throw new Error("no primary visible agent found")
          return visible
        })

        const defaultAgent = Effect.fnUntraced(function* () {
          return (yield* defaultInfo()).name
        })

        return {
          get,
          list,
          defaultInfo,
          defaultAgent,
        } satisfies State
      }),
    )

    return Service.of({
      get: Effect.fn("Agent.get")(function* (agent: string) {
        return yield* InstanceState.useEffect(state, (s) => s.get(agent))
      }),
      list: Effect.fn("Agent.list")(function* () {
        return yield* InstanceState.useEffect(state, (s) => s.list())
      }),
      defaultInfo: Effect.fn("Agent.defaultInfo")(function* () {
        return yield* InstanceState.useEffect(state, (s) => s.defaultInfo())
      }),
      defaultAgent: Effect.fn("Agent.defaultAgent")(function* () {
        return yield* InstanceState.useEffect(state, (s) => s.defaultAgent())
      }),
      generate: Effect.fn("Agent.generate")(function* (input: {
        description: string
        model?: { providerID: ProviderV2.ID; modelID: ModelV2.ID }
      }) {
        const cfg = yield* config.get()
        const model = input.model ?? (yield* provider.defaultModel())
        const resolved = yield* provider.getModel(model.providerID, model.modelID)
        const language = yield* provider.getLanguage(resolved)
        const tracer = cfg.experimental?.openTelemetry
          ? Option.getOrUndefined(yield* Effect.serviceOption(OtelTracer.OtelTracer))
          : undefined

        const system = [PROMPT_GENERATE]
        yield* plugin.trigger("experimental.chat.system.transform", { model: resolved }, { system })
        const existing = yield* InstanceState.useEffect(state, (s) => s.list())

        // TODO: clean this up so provider specific logic doesnt bleed over
        const authInfo = yield* auth.get(model.providerID).pipe(Effect.orDie)
        const isOpenaiOauth = model.providerID === "openai" && authInfo?.type === "oauth"

        const params = {
          experimental_telemetry: {
            isEnabled: cfg.experimental?.openTelemetry,
            tracer,
            metadata: {
              userId: cfg.username ?? "unknown",
            },
          },
          temperature: 0.3,
          messages: [
            ...(isOpenaiOauth
              ? []
              : system.map(
                  (item): ModelMessage => ({
                    role: "system",
                    content: item,
                  }),
                )),
            {
              role: "user",
              content: `Create an agent configuration based on this request: "${input.description}".\n\nIMPORTANT: The following identifiers already exist and must NOT be used: ${existing.map((i) => i.name).join(", ")}\n  Return ONLY the JSON object, no other text, do not wrap in backticks`,
            },
          ],
          model: language,
          schema: Object.assign(
            Schema.toStandardSchemaV1(GeneratedAgent),
            Schema.toStandardJSONSchemaV1(GeneratedAgent),
          ),
        } satisfies Parameters<typeof generateObject>[0]

        if (isOpenaiOauth) {
          return yield* Effect.promise(async () => {
            const result = streamObject({
              ...params,
              providerOptions: ProviderTransform.providerOptions(resolved, {
                instructions: system.join("\n"),
                store: false,
              }),
              onError: () => {},
            })
            for await (const part of result.fullStream) {
              if (part.type === "error") throw part.error
            }
            return result.object
          })
        }

        return yield* Effect.promise(() => generateObject(params).then((r) => r.object))
      }),
    })
  }),
)

const locationServiceMapNode = LayerNode.make({
  service: LocationServiceMap.Service,
  layer: locationServiceMapLayer,
  deps: [],
})

export const node = LayerNode.make({
  service: Service,
  layer: layer,
  deps: [Config.node, Auth.node, Plugin.node, Skill.node, Provider.node, locationServiceMapNode],
})

export * as Agent from "./agent"
