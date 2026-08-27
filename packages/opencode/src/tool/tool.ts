import { PermissionV1 } from "@auditcode/core/v1/permission"
import { Effect, Schema } from "effect"
import { SessionV1 } from "@auditcode/core/v1/session"
import type { JSONSchema7 } from "@ai-sdk/provider"
import type { MessageV2 } from "../session/message-v2"
import type { Permission } from "../permission"
import type { SessionID, MessageID } from "../session/schema"
import * as Truncate from "./truncate"
import { Agent } from "@/agent/agent"

interface Metadata {
  [key: string]: any
}

// TODO: remove this hack
export type DynamicDescription = (agent: Agent.Info) => Effect.Effect<string>

/**
 * Raised when the LLM calls a tool with arguments that fail the parameter
 * schema. This is the canonical "rewrite the input" tool error: the typed
 * error class makes it matchable upstream, and its `message` getter produces
 * the model-facing prose that the AI SDK feeds back as the tool result.
 */
export class InvalidArgumentsError extends Schema.TaggedErrorClass<InvalidArgumentsError>()(
  "ToolInvalidArgumentsError",
  {
    tool: Schema.String,
    detail: Schema.String,
  },
) {
  override get message() {
    return `The ${this.tool} tool was called with invalid arguments: ${this.detail}.\nPlease rewrite the input so it satisfies the expected schema.`
  }
}

export type Context<M extends Metadata = Metadata> = {
  sessionID: SessionID
  messageID: MessageID
  agent: string
  abort: AbortSignal
  callID?: string
  extra?: { [key: string]: unknown }
  messages: SessionV1.WithParts[]
  metadata(input: { title?: string; metadata?: M }): Effect.Effect<void>
  ask(input: Omit<PermissionV1.Request, "id" | "sessionID" | "tool">): Effect.Effect<void>
}

export interface ExecuteResult<M extends Metadata = Metadata> {
  title: string
  metadata: M
  output: string
  attachments?: Omit<SessionV1.FilePart, "id" | "sessionID" | "messageID">[]
}

export interface Def<
  Parameters extends Schema.Decoder<unknown> = Schema.Decoder<unknown>,
  M extends Metadata = Metadata,
> {
  id: string
  description: string
  parameters: Parameters
  jsonSchema?: JSONSchema7
  execute(args: Schema.Schema.Type<Parameters>, ctx: Context): Effect.Effect<ExecuteResult<M>>
  formatValidationError?(error: unknown): string
}
export type DefWithoutID<
  Parameters extends Schema.Decoder<unknown> = Schema.Decoder<unknown>,
  M extends Metadata = Metadata,
> = Omit<Def<Parameters, M>, "id">

export interface Info<
  Parameters extends Schema.Decoder<unknown> = Schema.Decoder<unknown>,
  M extends Metadata = Metadata,
> {
  id: string
  init: () => Effect.Effect<DefWithoutID<Parameters, M>>
}

type Init<Parameters extends Schema.Decoder<unknown>, M extends Metadata> =
  | DefWithoutID<Parameters, M>
  | (() => Effect.Effect<DefWithoutID<Parameters, M>>)

export type InferParameters<T> =
  T extends Info<infer P, any>
    ? Schema.Schema.Type<P>
    : T extends Effect.Effect<Info<infer P, any>, any, any>
      ? Schema.Schema.Type<P>
      : never
export type InferMetadata<T> =
  T extends Info<any, infer M> ? M : T extends Effect.Effect<Info<any, infer M>, any, any> ? M : never

export type InferDef<T> =
  T extends Info<infer P, infer M>
    ? Def<P, M>
    : T extends Effect.Effect<Info<infer P, infer M>, any, any>
      ? Def<P, M>
      : never

// #2a: graduated anti-solo-takeover rail. In the field the coordinator (agent
// "pentest") kept doing operational work itself (72 bash + 17 write + 3 edit in ONE
// run) instead of delegating — ballooning its own context (68% of the run's
// cache-read) and never standing up a real pivot. Count the coordinator's
// consecutive operational tool-calls WITHOUT a dispatch: nudge at WARN (advisory
// prepended to the tool output), hard-block at BLOCK (refuse to run). Reset on any
// delegation (task / task_graph plan). recon/read/state calls are never counted or
// blocked, so the coordinator can always observe + re-plan. Headless-safe (no
// permission.ask/TTY dependency). Only the "pentest" coordinator is subject to it —
// subagents (exploiter, post_exploit, …) run operational tools freely.
const COORDINATOR_AGENT = "audit"
const OPERATIONAL_TOOL_IDS = new Set(["bash", "write", "edit"])
const soloOpCount = new Map<string, number>()
const soloEnvInt = (name: string, fallback: number) => {
  const parsed = Number.parseInt(process.env[name] ?? "", 10)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}
const SOLO_WARN_OPS = soloEnvInt("OPENCODE_COORD_SOLO_WARN_OPS", 6)
const SOLO_BLOCK_OPS = soloEnvInt("OPENCODE_COORD_SOLO_BLOCK_OPS", 12)
function isDispatchCall(id: string, args: unknown): boolean {
  if (id === "task") return true
  if (id === "task_graph") return (args as { action?: unknown } | null)?.action === "plan"
  return false
}
function soloDelegateBanner(n: number): string {
  return (
    `<delegate-now ops="${n}">\n` +
    `You (coordinator) have run ${n} operational commands (bash/write/edit) in a row WITHOUT delegating. ` +
    `Operational work — exploit builds, shell/tunnel setup, deep enumeration — is a SUBAGENT's job; doing it ` +
    `yourself balloons your context and stalls coordination (the #1 failure mode). Dispatch it via task / ` +
    `task_graph plan NOW and keep only planning + state/recon reads for yourself.\n</delegate-now>\n\n`
  )
}
function soloBlockedOutput(n: number): string {
  return (
    `BLOCKED (anti-solo-grind): you have run ${n} operational commands without delegating. Operational work ` +
    `MUST be delegated — call task / task_graph plan to dispatch a subagent for this exact work. state_query / ` +
    `state_update / read stay available so you can observe and plan. This block clears the moment you dispatch.`
  )
}
export type SoloRailAction = { kind: "run" } | { kind: "warn"; count: number } | { kind: "block"; count: number }
// Pure decision for the anti-solo rail — extracted so it is unit-testable. Given the
// prior op-count for a session and this tool call, returns the new count + what to do.
// Non-coordinator or non-operational calls run untouched; a dispatch resets to 0.
export function soloRailStep(
  prevCount: number,
  agent: string,
  id: string,
  args: unknown,
  warn: number,
  block: number,
): { count: number; action: SoloRailAction } {
  if (agent !== COORDINATOR_AGENT) return { count: prevCount, action: { kind: "run" } }
  if (isDispatchCall(id, args)) return { count: 0, action: { kind: "run" } }
  if (!OPERATIONAL_TOOL_IDS.has(id)) return { count: prevCount, action: { kind: "run" } }
  const count = prevCount + 1
  if (count > block) return { count, action: { kind: "block", count } }
  if (count > warn) return { count, action: { kind: "warn", count } }
  return { count, action: { kind: "run" } }
}

function wrap<Parameters extends Schema.Decoder<unknown>, Result extends Metadata>(
  id: string,
  init: Init<Parameters, Result>,
  truncate: Truncate.Interface,
  agents: Agent.Interface,
) {
  return () =>
    Effect.gen(function* () {
      const toolInfo = typeof init === "function" ? { ...(yield* init()) } : { ...init }
      // Compile the parser closure once per tool init; `decodeUnknownEffect`
      // allocates a new closure per call, so hoisting avoids re-closing it for
      // every LLM tool invocation.
      const decode = Schema.decodeUnknownEffect(toolInfo.parameters)
      const execute = toolInfo.execute
      toolInfo.execute = (args, ctx) => {
        const attrs = {
          "tool.name": id,
          "session.id": ctx.sessionID,
          "message.id": ctx.messageID,
          ...(ctx.callID ? { "tool.call_id": ctx.callID } : {}),
        }
        return Effect.gen(function* () {
          // #2a anti-solo-takeover rail (coordinator only).
          let soloBanner = ""
          if (ctx.agent === COORDINATOR_AGENT) {
            const prev = soloOpCount.get(ctx.sessionID) ?? 0
            const step = soloRailStep(prev, ctx.agent, id, args, SOLO_WARN_OPS, SOLO_BLOCK_OPS)
            soloOpCount.set(ctx.sessionID, step.count)
            if (step.action.kind === "block") {
              return { title: "Delegate first", metadata: {} as Result, output: soloBlockedOutput(step.action.count) }
            }
            if (step.action.kind === "warn") soloBanner = soloDelegateBanner(step.action.count)
          }
          const decoded = yield* decode(args).pipe(
            Effect.mapError(
              (error) =>
                new InvalidArgumentsError({
                  tool: id,
                  detail: toolInfo.formatValidationError ? toolInfo.formatValidationError(error) : String(error),
                }),
            ),
          )
          const executed = yield* execute(decoded as Schema.Schema.Type<Parameters>, ctx)
          const result = soloBanner ? { ...executed, output: soloBanner + executed.output } : executed
          if (result.metadata.truncated !== undefined) {
            return result
          }
          const agent = yield* agents.get(ctx.agent)
          const truncated = yield* truncate.output(result.output, {}, agent)
          return {
            ...result,
            output: truncated.content,
            metadata: {
              ...result.metadata,
              truncated: truncated.truncated,
              ...(truncated.truncated && { outputPath: truncated.outputPath }),
            },
          }
        }).pipe(Effect.orDie, Effect.withSpan("Tool.execute", { attributes: attrs }))
      }
      return toolInfo
    })
}

export function define<
  Parameters extends Schema.Decoder<unknown>,
  Result extends Metadata,
  R,
  ID extends string = string,
>(
  id: ID,
  init: Effect.Effect<Init<Parameters, Result>, never, R>,
): Effect.Effect<Info<Parameters, Result>, never, R | Truncate.Service | Agent.Service> & { id: ID } {
  return Object.assign(
    Effect.gen(function* () {
      const resolved = yield* init
      const truncate = yield* Truncate.Service
      const agents = yield* Agent.Service
      return { id, init: wrap(id, resolved, truncate, agents) }
    }),
    { id },
  )
}

export function init<P extends Schema.Decoder<unknown>, M extends Metadata>(
  info: Info<P, M>,
): Effect.Effect<Def<P, M>> {
  return Effect.gen(function* () {
    const init = yield* info.init()
    return {
      ...init,
      id: info.id,
    }
  })
}

export * as Tool from "./tool"
