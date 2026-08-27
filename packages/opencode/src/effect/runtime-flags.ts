import { Config, ConfigProvider, Context, Effect, Layer, Option } from "effect"
import { ConfigService } from "@/effect/config-service"

const bool = (name: string) => Config.boolean(name).pipe(Config.withDefault(false))
const positiveInteger = (name: string) =>
  Config.number(name).pipe(
    Config.map((value) => (Number.isInteger(value) && value > 0 ? value : undefined)),
    Config.orElse(() => Config.succeed(undefined)),
  )
const experimental = bool("OPENCODE_EXPERIMENTAL")
const enabledByExperimental = (name: string) =>
  Config.all({ experimental, enabled: Config.boolean(name).pipe(Config.option) }).pipe(
    Config.map((flags) => Option.getOrElse(flags.enabled, () => flags.experimental)),
  )

export class Service extends ConfigService.Service<Service>()("@auditcode/RuntimeFlags", {
  autoShare: bool("OPENCODE_AUTO_SHARE"),
  pure: bool("OPENCODE_PURE"),
  disableDefaultPlugins: bool("OPENCODE_DISABLE_DEFAULT_PLUGINS"),
  disableEmbeddedWebUi: bool("OPENCODE_DISABLE_EMBEDDED_WEB_UI"),
  disableExternalSkills: bool("OPENCODE_DISABLE_EXTERNAL_SKILLS"),
  disableLspDownload: bool("OPENCODE_DISABLE_LSP_DOWNLOAD"),
  disableClaudeCodePrompt: Config.all({
    broad: bool("OPENCODE_DISABLE_CLAUDE_CODE"),
    direct: bool("OPENCODE_DISABLE_CLAUDE_CODE_PROMPT"),
  }).pipe(Config.map((flags) => flags.broad || flags.direct)),
  disableClaudeCodeSkills: Config.all({
    broad: bool("OPENCODE_DISABLE_CLAUDE_CODE"),
    direct: bool("OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"),
  }).pipe(Config.map((flags) => flags.broad || flags.direct)),
  enableExa: Config.all({
    experimental,
    enabled: bool("OPENCODE_ENABLE_EXA"),
    legacy: bool("OPENCODE_EXPERIMENTAL_EXA"),
  }).pipe(Config.map((flags) => flags.experimental || flags.enabled || flags.legacy)),
  enableParallel: Config.all({
    enabled: bool("OPENCODE_ENABLE_PARALLEL"),
    legacy: bool("OPENCODE_EXPERIMENTAL_PARALLEL"),
  }).pipe(Config.map((flags) => flags.enabled || flags.legacy)),
  enableExperimentalModels: bool("OPENCODE_ENABLE_EXPERIMENTAL_MODELS"),
  enableQuestionTool: bool("OPENCODE_ENABLE_QUESTION_TOOL"),
  experimentalReferences: enabledByExperimental("OPENCODE_EXPERIMENTAL_REFERENCES"),
  experimentalBackgroundSubagents: enabledByExperimental("OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS"),
  // Deterministic orchestrator — DEFAULT ON as of 0.2.2 (validated on a real
  // multi-host pivot run: healthy dispatch, overload -87%, authentic lateral
  // movement). Kill-switch: OPENCODE_DISABLE_ORCHESTRATOR=true falls back to the
  // manual task_graph/task path if a regression surfaces in the wild. (Field
  // name kept as-is to avoid churn across call sites; it is no longer gated by
  // OPENCODE_EXPERIMENTAL_ORCHESTRATOR.)
  experimentalOrchestrator: bool("OPENCODE_DISABLE_ORCHESTRATOR").pipe(Config.map((disabled) => !disabled)),
  // Max subagents the orchestrator keeps in flight at once (rolling pipeline cap).
  orchestratorConcurrency: positiveInteger("OPENCODE_ORCHESTRATOR_CONCURRENCY"),
  // Delay in ms between spawns within a single pump, to pace provider load and
  // avoid bursting into rate limits. undefined -> code default.
  orchestratorStaggerMs: positiveInteger("OPENCODE_ORCHESTRATOR_STAGGER_MS"),
  // S-1: coalesce window (ms) for coordinator wake-ups. Subagent completions that
  // land within this window are batched into ONE synthetic coordinator turn
  // instead of N (each of which replays the full transcript). Dispatch is
  // unaffected — the rolling pump refills slots on every settle regardless.
  // undefined -> code default (1500). Set very low to approximate per-completion.
  orchestratorCoalesceMs: positiveInteger("OPENCODE_ORCHESTRATOR_COALESCE_MS"),
  // Stall watchdog: an in-flight task (dispatched/running) that has run longer
  // than this (ms) WHILE tasks depend on it and cannot start wakes the coordinator
  // to decide (kill/complete/re-plan). Guards against a subagent that never returns
  // stranding its dependents forever (the DAG-deadlock). undefined -> code default
  // (300000 = 5min). Lower it for fast-iterating benches.
  orchestratorStallMs: positiveInteger("OPENCODE_ORCHESTRATOR_STALL_MS"),
  // No-progress early-cut: when the fleet keeps spending (subagents in flight) but
  // ZERO new state markers (access/credential/host/objective) land for this many ms,
  // wake the coordinator ONCE with an advisory to cut the dead-end branch and pivot
  // (the dev.9 failure: 80% of the run poured into a pivot that scored nothing).
  // Advisory only — never auto-kills, so a hard-but-real grind can justify continuing.
  // undefined -> code default (1500000 = 25min). Progress-gated, NOT step-count.
  orchestratorNoProgressMs: positiveInteger("OPENCODE_ORCHESTRATOR_NOPROGRESS_MS"),
  // Safety rail: max concurrent shell execs targeting the SAME host IP. Commands to
  // one host beyond this serialize, so the fleet can't self-DoS a foothold/target by
  // hammering it in parallel (the dev.9 react-kill: 3 agents firing the stateless-RCE
  // driver concurrently crashed the app). undefined -> code default (2); set 1 to
  // fully serialize per host.
  perHostExecConcurrency: positiveInteger("OPENCODE_PER_HOST_EXEC_CONCURRENCY"),
  // Max concurrent main-model LLM streams per provider (coordinator + subagents).
  // Caps outbound concurrency so a fan-out doesn't saturate the provider into
  // 429/529 overloads. undefined -> code default. Small-model (offload/title)
  // streams use a separate, smaller pool.
  llmMaxConcurrency: positiveInteger("OPENCODE_LLM_MAX_CONCURRENCY"),
  experimentalLspTy: bool("OPENCODE_EXPERIMENTAL_LSP_TY"),
  experimentalLspTool: enabledByExperimental("OPENCODE_EXPERIMENTAL_LSP_TOOL"),
  experimentalOxfmt: enabledByExperimental("OPENCODE_EXPERIMENTAL_OXFMT"),
  experimentalPlanMode: enabledByExperimental("OPENCODE_EXPERIMENTAL_PLAN_MODE"),
  experimentalCodeMode: enabledByExperimental("OPENCODE_EXPERIMENTAL_CODE_MODE"),
  experimentalEventSystem: enabledByExperimental("OPENCODE_EXPERIMENTAL_EVENT_SYSTEM"),
  experimentalWorkspaces: enabledByExperimental("OPENCODE_EXPERIMENTAL_WORKSPACES"),
  experimentalIconDiscovery: enabledByExperimental("OPENCODE_EXPERIMENTAL_ICON_DISCOVERY"),
  outputTokenMax: positiveInteger("OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX"),
  bashDefaultTimeoutMs: positiveInteger("OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS"),
  experimentalNativeLlm: bool("OPENCODE_EXPERIMENTAL_NATIVE_LLM"),
  experimentalWebSockets: bool("OPENCODE_EXPERIMENTAL_WEBSOCKETS"),
  client: Config.string("OPENCODE_CLIENT").pipe(Config.withDefault("cli")),
}) {}

export type Info = Context.Service.Shape<typeof Service>

const emptyConfigLayer = Service.layer.pipe(
  Layer.provide(ConfigProvider.layer(ConfigProvider.fromUnknown({}))),
  Layer.orDie,
)

export const layer = (overrides: Partial<Info> = {}) =>
  Layer.effect(
    Service,
    Effect.gen(function* () {
      const flags = yield* Service
      return Service.of({ ...flags, ...overrides })
    }),
  ).pipe(Layer.provide(emptyConfigLayer))

export const node = LayerNode.make({ service: Service, layer: Service.layer.pipe(Layer.orDie), deps: [] })

export * as RuntimeFlags from "./runtime-flags"
import { LayerNode } from "@auditcode/core/effect/layer-node"
