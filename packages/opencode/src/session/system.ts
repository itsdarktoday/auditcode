import { LayerNode } from "@auditcode/core/effect/layer-node"
import { Context, Effect, Layer } from "effect"

import { InstanceState } from "@/effect/instance-state"

import PROMPT_AUDIT from "./prompt/audit.txt"
import PROMPT_KERNEL from "./prompt/kernel.txt"
import PROMPT_KERNEL_AUDIT from "./prompt/kernel-audit.txt"
import PROMPT_KERNEL_SUBAGENT from "./prompt/kernel-subagent.txt"

const DEEP_AUDIT_AGENTS = new Set([
  "math_precision",
  "access_control",
  "economic_security",
  "reentrancy",
  "invariant_agent",
  "periphery_agent",
  "boundary_agent",
  "poc_dev",
  "solana_analyst",
  "exploiter",
  "exploit_dev",
  "webapp",
])

import type { Provider } from "@/provider/provider"
import type { Agent } from "@/agent/agent"
import { Permission } from "@/permission"
import { Skill } from "@/skill"
import { AbsolutePath } from "@auditcode/core/schema"
import { Location } from "@auditcode/core/location"
import { LocationServiceMap, locationServiceMapLayer } from "@auditcode/core/location-services"
import { Reference } from "@auditcode/core/reference"
import { MCP } from "@/mcp"
import { PermissionV1 } from "@auditcode/core/v1/permission"
import { EngagementStore } from "@auditcode/core/engagement/store"

export function provider(model: Provider.Model) {
  // AuditCode: always use the audit coordinator prompt as the base
  return [PROMPT_AUDIT]
}

export interface Interface {
  readonly environment: (model: Provider.Model) => Effect.Effect<string[]>
  readonly kernel: (agent: Agent.Info) => Effect.Effect<string>
  readonly skills: (agent: Agent.Info) => Effect.Effect<string | undefined>
  readonly mcp: (agent: Agent.Info, permission?: PermissionV1.Ruleset) => Effect.Effect<string | undefined>
}

export class Service extends Context.Service<Service, Interface>()("@auditcode/SystemPrompt") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const skill = yield* Skill.Service
    const mcp = yield* MCP.Service
    const locations = yield* LocationServiceMap.Service
    const engagement = yield* EngagementStore.Service

    return Service.of({
      kernel: Effect.fn("SystemPrompt.kernel")(function* (agent: Agent.Info) {
        const parts = [PROMPT_KERNEL, PROMPT_KERNEL_AUDIT]
        if (agent.mode === "subagent") parts.push(PROMPT_KERNEL_SUBAGENT)
        return parts.join("\n\n")
      }),
      environment: Effect.fn("SystemPrompt.environment")(function* (model: Provider.Model) {
        const ctx = yield* InstanceState.context
        const references = yield* Effect.gen(function* () {
          return (yield* (yield* Reference.Service).list()).filter((reference) => reference.description !== undefined)
        }).pipe(Effect.provide(locations.get(Location.Ref.make({ directory: AbsolutePath.make(ctx.directory) }))))
        return [
          [
            `You are AuditCode, powered by model ${model.providerID}/${model.api.id}`,
            `Here is some useful information about the environment you are running in:`,
            `<env>`,
            `  Working directory: ${ctx.directory}`,
            `  Workspace root folder: ${ctx.worktree}`,
            `  Is directory a git repo: ${ctx.project.vcs === "git" ? "yes" : "no"}`,
            `  Platform: ${process.platform}`,
            `  Today's date: ${new Date().toDateString()}`,
            `</env>`,
          ].join("\n"),
          references.length === 0
            ? undefined
            : [
                "Project references provide additional directories that can be accessed when relevant.",
                "<available_references>",
                ...references
                  .toSorted((a, b) => a.name.localeCompare(b.name))
                  .flatMap((reference) => [
                    "  <reference>",
                    `    <name>${reference.name}</name>`,
                    `    <path>${reference.path}</path>`,
                    ...(reference.description === undefined
                      ? []
                      : [`    <description>${reference.description}</description>`]),
                    "  </reference>",
                  ]),
                "</available_references>",
              ].join("\n"),
        ].filter((part): part is string => part !== undefined)
      }),

      skills: Effect.fn("SystemPrompt.skills")(function* (agent: Agent.Info) {
        if (Permission.disabled(["skill"], agent.permission).has("skill")) return

        const list = yield* skill.available(agent)
        const state = yield* engagement.get().pipe(Effect.catch(() => Effect.succeed(undefined)))
        const scoped = state?.current_phase ? Skill.scopeByTags(list, [state.current_phase]) : list

        return [
          "Skills provide specialized instructions and workflows for specific tasks.",
          "Use the skill tool to load a skill when a task matches its description.",
          Skill.fmt(scoped, { verbose: true }),
        ].join("\n")
      }),

      mcp: Effect.fn("SystemPrompt.mcp")(function* (agent: Agent.Info, permission?: PermissionV1.Ruleset) {
        const ruleset = Permission.merge(agent.permission, permission ?? [])
        const instructions = (yield* mcp.instructions()).filter(
          (item) => item.tools.length === 0 || Permission.disabled(item.tools, ruleset).size < item.tools.length,
        )
        if (instructions.length === 0) return

        return [
          "<mcp_instructions>",
          ...instructions.flatMap((item) => [
            `  <server name="${item.name}">`,
            ...item.instructions.split("\n").map((line) => `    ${line}`),
            "  </server>",
          ]),
          "</mcp_instructions>",
        ].join("\n")
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
  deps: [Skill.node, MCP.node, locationServiceMapNode, EngagementStore.node],
})

export * as SystemPrompt from "./system"
