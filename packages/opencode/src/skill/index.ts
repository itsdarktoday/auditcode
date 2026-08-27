import { LayerNode } from "@auditcode/core/effect/layer-node"
import path from "path"
import { realpathSync } from "fs"
import { Effect, Layer, Context, Schema } from "effect"
import { NamedError } from "@auditcode/core/util/error"
import type { Agent } from "@/agent/agent"
import { EventV2Bridge } from "@/event-v2-bridge"
import { InstanceState } from "@/effect/instance-state"
import { Global } from "@auditcode/core/global"
import { SkillPlugin } from "@auditcode/core/plugin/skill"
import { Permission } from "@/permission"
import { FSUtil } from "@auditcode/core/fs-util"
import { Config } from "@/config/config"
import { FrontmatterError } from "@auditcode/core/v1/config/error"
import { ConfigMarkdown } from "@/config/markdown"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { Glob } from "@auditcode/core/util/glob"
import { Discovery } from "./discovery"
import { BundledSkills } from "./bundled"
import { SkillMigrate } from "./migrate"
import { isRecord } from "@/util/record"
import { escapeHtml } from "@/util/html"

const CLAUDE_EXTERNAL_DIR = ".claude"
const AGENTS_EXTERNAL_DIR = ".agents"
const EXTERNAL_SKILL_PATTERN = "skills/**/SKILL.md"
const OPENCODE_SKILL_PATTERN = "{skill,skills}/**/SKILL.md"
const SKILL_PATTERN = "**/SKILL.md"

// Provenance layers for a discovered skill. Precedence is by priority: a
// higher-priority layer shadows a lower one when two skills share a `name`.
// bundled (ships with the binary) < pack (imported/community) < user
// (user-authored & forks) < project (repo-local .auditcode/.claude).
// `legacy` is the pre-layered flat ~/.auditcode/skills root, kept as a
// deprecation fallback until migration runs; it sits just above bundled.
// `builtin` is reserved for skills registered in-code so any on-disk skill of
// the same name overrides them without a duplicate warning.
type SkillLayer = "builtin" | "bundled" | "legacy" | "pack" | "user" | "project"
const LAYER_PRIORITY: Record<SkillLayer, number> = {
  builtin: -1,
  bundled: 0,
  legacy: 1,
  pack: 2,
  user: 3,
  project: 4,
}
type MatchRecord = { path: string; layer: SkillLayer; source: string }

// Resolve symlinks to a canonical absolute path. Falls back to the input when
// the path does not exist (nothing to resolve yet).
function canonicalize(p: string): string {
  try {
    return realpathSync.native(p)
  } catch {
    return p
  }
}

// Built-in skill that ships with auditcode. The model's intuition for what an
// auditcode.json should look like is often wrong, and auditcode hard-fails on
// invalid config, so users hit cryptic startup errors. Loading this skill
// when the model is asked to touch auditcode's own config files gives it the
// actual schemas instead of guesses.
const CUSTOMIZE_AUDITCODE_SKILL_NAME = "customize-auditcode"
const CUSTOMIZE_AUDITCODE_SKILL_DESCRIPTION =
  "Use ONLY when the user is editing or creating auditcode's own configuration: auditcode.json, auditcode.jsonc, files under .auditcode/, or files under ~/.config/auditcode/. Also use when creating or fixing auditcode agents, subagents, skills, plugins, MCP servers, or permission rules. Do not use for the user's own application code, or for any project that is not configuring auditcode itself."
const CUSTOMIZE_AUDITCODE_SKILL_BODY = SkillPlugin.CustomizeAuditcodeContent

export const Info = Schema.Struct({
  name: Schema.String,
  description: Schema.optional(Schema.String),
  location: Schema.String,
  content: Schema.String,
  // Provenance — set by discovery. Optional so external constructors (and the
  // in-code built-in skill) stay valid. `layer` drives override precedence;
  // `source` records where the skill came from (for `skills list` diagnostics).
  layer: Schema.optional(Schema.String),
  source: Schema.optional(Schema.String),
  // Optional metadata read from SKILL.md frontmatter (all backward-compatible;
  // absent fields are simply undefined). `requires.auditcode` is a min-host
  // semver range — enforced as warn-and-load (see `skills doctor`), never a
  // hard failure, so a live engagement is never bricked.
  version: Schema.optional(Schema.String),
  id: Schema.optional(Schema.String),
  author: Schema.optional(Schema.String),
  tags: Schema.optional(Schema.Array(Schema.String)),
  dependencies: Schema.optional(Schema.Array(Schema.String)),
  requires: Schema.optional(Schema.Struct({ auditcode: Schema.optional(Schema.String) })),
  license: Schema.optional(Schema.String),
})
export type Info = Schema.Schema.Type<typeof Info>

const Issue = Schema.StructWithRest(
  Schema.Struct({
    message: Schema.String,
    path: Schema.Array(Schema.String),
  }),
  [Schema.Record(Schema.String, Schema.Unknown)],
)

function isSkillFrontmatter(data: unknown): data is { name: string; description?: string } {
  return (
    isRecord(data) &&
    typeof data.name === "string" &&
    (data.description === undefined || typeof data.description === "string")
  )
}

type SkillMeta = Pick<Info, "version" | "id" | "author" | "tags" | "dependencies" | "requires" | "license">

// Defensively read optional metadata from raw (untrusted) YAML frontmatter.
// Wrong-typed values are ignored rather than rejected — the skill still loads.
function readSkillMeta(data: Record<string, unknown>): SkillMeta {
  const str = (v: unknown) => (typeof v === "string" ? v : undefined)
  const strArray = (v: unknown) =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : undefined
  const tags = strArray(data.tags)
  const dependencies = strArray(data.dependencies)
  const requiresRaw = isRecord(data.requires) ? str(data.requires.auditcode) : undefined
  return {
    version: str(data.version),
    id: str(data.id),
    author: str(data.author),
    tags: tags && tags.length > 0 ? tags : undefined,
    dependencies: dependencies && dependencies.length > 0 ? dependencies : undefined,
    requires: requiresRaw ? { auditcode: requiresRaw } : undefined,
    license: str(data.license),
  }
}

export class InvalidError extends Schema.TaggedErrorClass<InvalidError>()("SkillInvalidError", {
  path: Schema.String,
  message: Schema.optional(Schema.String),
  issues: Schema.optional(Schema.Array(Issue)),
}) {}

export class NameMismatchError extends Schema.TaggedErrorClass<NameMismatchError>()("SkillNameMismatchError", {
  path: Schema.String,
  expected: Schema.String,
  actual: Schema.String,
}) {}

export class NotFoundError extends Schema.TaggedErrorClass<NotFoundError>()("Skill.NotFoundError", {
  name: Schema.String,
  available: Schema.Array(Schema.String),
}) {
  override get message() {
    return `Skill "${this.name}" not found. Available skills: ${this.available.join(", ") || "none"}`
  }
}

type State = {
  skills: Record<string, Info>
  dirs: Set<string>
}

type DiscoveryState = {
  matches: MatchRecord[]
  dirs: string[]
}

type ScanState = {
  matches: Map<string, MatchRecord>
  dirs: Set<string>
}

export interface Interface {
  readonly get: (name: string) => Effect.Effect<Info | undefined>
  readonly require: (name: string) => Effect.Effect<Info, NotFoundError>
  readonly all: () => Effect.Effect<Info[]>
  readonly dirs: () => Effect.Effect<string[]>
  readonly available: (agent?: Agent.Info) => Effect.Effect<Info[]>
}

const parseMatch = Effect.fnUntraced(function* (record: MatchRecord, events: EventV2Bridge.Service["Service"]) {
  const match = record.path
  const md = yield* Effect.tryPromise({
    try: () => ConfigMarkdown.parse(match),
    catch: (err) => err,
  }).pipe(
    Effect.catch(
      Effect.fnUntraced(function* (err) {
        const message = FrontmatterError.isInstance(err) ? err.data.message : `Failed to parse skill ${match}`
        const { Session } = yield* Effect.promise(() => import("@/session/session"))
        yield* events.publish(Session.Event.Error, { error: new NamedError.Unknown({ message }).toObject() })
        yield* Effect.logError("failed to load skill", { skill: match, error: err })
        return undefined
      }),
    ),
  )

  if (!md) return undefined
  if (!isSkillFrontmatter(md.data)) return undefined

  return {
    record,
    name: md.data.name,
    description: md.data.description,
    content: md.content,
    meta: readSkillMeta(md.data),
  }
})

const scan = Effect.fnUntraced(function* (
  state: ScanState,
  root: string,
  pattern: string,
  opts: { layer: SkillLayer; source: string; dot?: boolean; scope?: string; exclude?: string[] },
) {
  const matches = yield* Effect.tryPromise({
    try: () =>
      Glob.scan(pattern, {
        cwd: root,
        absolute: true,
        include: "file",
        symlink: true,
        dot: opts.dot,
      }),
    catch: (error) => error,
  }).pipe(
    Effect.catch((error) => {
      if (!opts.scope) return Effect.die(error)
      return Effect.logError(`failed to scan ${opts.scope} skills`, { dir: root, error: error }).pipe(
        Effect.as([] as string[]),
      )
    }),
  )

  // Canonicalize so the same physical file always yields the same key: two
  // roots reaching one file via different symlink forms (e.g. the global home
  // and a config dir that both cover ~/.auditcode/skills) must dedupe to one
  // entry, or the has()-guard misses and a lower-provenance file is claimed
  // under the wrong layer.
  const excludes = (opts.exclude ?? []).map((prefix) => {
    const trimmed = prefix.endsWith(path.sep) ? prefix.slice(0, -1) : prefix
    return canonicalize(trimmed) + path.sep
  })

  for (const raw of matches) {
    const match = canonicalize(raw)
    // Skip paths under an excluded prefix (e.g. the layered subdirs when
    // scanning the legacy flat root, so they aren't double-claimed).
    if (excludes.some((prefix) => match.startsWith(prefix))) continue
    // First scan to claim a path fixes its layer; later scans don't reclaim it.
    if (!state.matches.has(match)) state.matches.set(match, { path: match, layer: opts.layer, source: opts.source })
    state.dirs.add(path.dirname(match))
  }
})

const discoverSkills = Effect.fnUntraced(function* (
  config: Config.Interface,
  discovery: Discovery.Interface,
  fsys: FSUtil.Interface,
  global: Global.Interface,
  disableExternalSkills: boolean,
  disableClaudeCodeSkills: boolean,
  directory: string,
  worktree: string,
) {
  const state: ScanState = { matches: new Map(), dirs: new Set() }

  const externalDirs: string[] = []
  if (!disableExternalSkills) {
    if (!disableClaudeCodeSkills) externalDirs.push(CLAUDE_EXTERNAL_DIR)
    externalDirs.push(AGENTS_EXTERNAL_DIR)

    // Global ~/.claude/skills, ~/.agents/skills → user layer.
    for (const dir of externalDirs) {
      const root = path.join(global.home, dir)
      if (!(yield* fsys.isDir(root))) continue
      yield* scan(state, root, EXTERNAL_SKILL_PATTERN, {
        dot: true,
        scope: "global",
        layer: "user",
        source: `external:${dir}`,
      })
    }

    // Repo-local .claude/.agents up-dirs → project layer (highest precedence).
    const upDirs = yield* fsys
      .up({ targets: externalDirs, start: directory, stop: worktree })
      .pipe(Effect.catch(() => Effect.succeed([] as string[])))

    for (const root of upDirs) {
      yield* scan(state, root, EXTERNAL_SKILL_PATTERN, {
        dot: true,
        scope: "project",
        layer: "project",
        source: `project:${root}`,
      })
    }
  }

  // Global skills home: always discoverable regardless of cwd. Engagements are
  // global (~/.auditcode/engagements), so sessions run from arbitrary
  // directories; skills placed here load everywhere. Physically separated into
  // provenance layers — see SkillLayer. Updates only ever rewrite the layer
  // they own, so user/ and packs/ survive a bundled refresh.
  //
  // MUST run before the config-dir scan below: config.directories() includes
  // ${home}/.auditcode and scans it with `{skill,skills}/**`, which would
  // otherwise match these same files first and mis-claim them as `project`.
  // First-claim-wins in scan(), so claiming the correct layer here comes first.
  const globalSkills = path.join(global.home, ".auditcode", "skills")
  if (yield* fsys.isDir(globalSkills)) {
    const bundled = path.join(globalSkills, "bundled")
    const packs = path.join(globalSkills, "packs")
    const userDir = path.join(globalSkills, "user")
    const disabled = path.join(globalSkills, "disabled")

    if (yield* fsys.isDir(bundled)) yield* scan(state, bundled, SKILL_PATTERN, { layer: "bundled", source: "bundled" })
    if (yield* fsys.isDir(packs)) yield* scan(state, packs, SKILL_PATTERN, { layer: "pack", source: "packs" })
    if (yield* fsys.isDir(userDir)) yield* scan(state, userDir, SKILL_PATTERN, { layer: "user", source: "user" })

    // Legacy flat layout (pre-layered): scan the home root but exclude the
    // managed subdirs and the disabled quarantine. Deprecation fallback until
    // migration (P5) relocates these into user/. disabled/ is never scanned.
    yield* scan(state, globalSkills, SKILL_PATTERN, {
      layer: "legacy",
      source: "legacy",
      exclude: [bundled, packs, userDir, disabled].map((d) => d + path.sep),
    })
  }

  // Config directories (repo-local .auditcode + global config) → project layer.
  // config.directories() includes ${home}/.auditcode, and OPENCODE_SKILL_PATTERN
  // (`{skill,skills}/**`) would otherwise reach into the managed global skills
  // home (${home}/.auditcode/skills/**), re-discovering bundled/pack/user and
  // even disabled/ skills under the wrong (project) layer. That subtree is owned
  // by the global-home block above, so exclude it here.
  const configDirs = yield* config.directories()
  for (const dir of configDirs) {
    yield* scan(state, dir, OPENCODE_SKILL_PATTERN, {
      layer: "project",
      source: `config:${dir}`,
      exclude: [globalSkills + path.sep],
    })
  }

  const cfg = yield* config.get()
  for (const item of cfg.skills?.paths ?? []) {
    const expanded = item.startsWith("~/") ? path.join(global.home, item.slice(2)) : item
    // A relative skill path must not depend on the session cwd, which is
    // arbitrary for global engagements. Resolve it against the session
    // directory AND the project root of every discovered config dir (e.g. the
    // parent of <root>/.auditcode), scanning whichever exist.
    const candidates = path.isAbsolute(expanded)
      ? [expanded]
      : [path.join(directory, expanded), ...configDirs.map((d) => path.join(path.dirname(d), expanded))]
    const seen = new Set<string>()
    let found = false
    for (const dir of candidates) {
      if (seen.has(dir)) continue
      seen.add(dir)
      if (!(yield* fsys.isDir(dir))) continue
      found = true
      yield* scan(state, dir, SKILL_PATTERN, { layer: "user", source: `path:${item}` })
    }
    if (!found) {
      yield* Effect.logWarning("skill path not found", { path: expanded, candidates: Array.from(seen) })
    }
  }

  for (const url of cfg.skills?.urls ?? []) {
    const pulledDirs = yield* discovery.pull(url)
    for (const dir of pulledDirs) {
      yield* scan(state, dir, SKILL_PATTERN, { layer: "pack", source: `url:${url}` })
    }
  }

  return {
    matches: Array.from(state.matches.values()),
    dirs: Array.from(state.dirs),
  }
})

const loadSkills = Effect.fnUntraced(function* (
  state: State,
  discovered: DiscoveryState,
  events: EventV2Bridge.Service["Service"],
) {
  // Parse concurrently (I/O bound), then resolve precedence in a single
  // deterministic pass. Resolution must not depend on parse-completion order,
  // so we sort by (layer priority asc, path asc) and let a higher-priority
  // layer shadow a lower one. Same-name skills within one layer are a real
  // duplicate: the lexicographically-first path wins and the rest warn.
  const parsed = yield* Effect.forEach(discovered.matches, (record) => parseMatch(record, events), {
    concurrency: "unbounded",
  })
  const skills = parsed.filter((p): p is NonNullable<typeof p> => p !== undefined)
  skills.sort((a, b) => {
    const pa = LAYER_PRIORITY[a.record.layer]
    const pb = LAYER_PRIORITY[b.record.layer]
    if (pa !== pb) return pa - pb
    return a.record.path.localeCompare(b.record.path)
  })

  for (const skill of skills) {
    const existing = state.skills[skill.name]
    const priority = LAYER_PRIORITY[skill.record.layer]
    if (existing) {
      const existingPriority = LAYER_PRIORITY[(existing.layer as SkillLayer | undefined) ?? "builtin"]
      if (priority < existingPriority) continue
      if (priority === existingPriority) {
        yield* Effect.logWarning("duplicate skill name in same layer", {
          name: skill.name,
          layer: skill.record.layer,
          existing: existing.location,
          duplicate: skill.record.path,
        })
        continue
      }
      // priority > existingPriority: higher layer shadows the lower one.
    }
    state.dirs.add(path.dirname(skill.record.path))
    state.skills[skill.name] = {
      name: skill.name,
      description: skill.description,
      location: skill.record.path,
      content: skill.content,
      layer: skill.record.layer,
      source: skill.record.source,
      ...skill.meta,
    }
  }

  yield* Effect.logInfo("init", { count: Object.keys(state.skills).length })
})

export class Service extends Context.Service<Service, Interface>()("@auditcode/Skill") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const discovery = yield* Discovery.Service
    const config = yield* Config.Service
    const events = yield* EventV2Bridge.Service
    const fsys = yield* FSUtil.Service
    const global = yield* Global.Service
    const flags = yield* RuntimeFlags.Service
    // Seed/refresh ~/.auditcode/skills/bundled from the binary-embedded set
    // before any discovery runs. Best-effort and no-op in dev (not embedded).
    yield* BundledSkills.seed(fsys, global)
    // One-time migration of the pre-layered flat layout into user/ (runs after
    // seeding so bundled/.manifest.json checksums are available to classify
    // pristine-vs-modified). Best-effort; idempotent once no legacy files remain.
    yield* Effect.tryPromise(() => SkillMigrate.run(global.home)).pipe(
      Effect.catch((error) => Effect.logError("skill layout migration failed", { error })),
    )
    const discovered = yield* InstanceState.make(
      Effect.fn("Skill.discovery")(function* (ctx) {
        return yield* discoverSkills(
          config,
          discovery,
          fsys,
          global,
          flags.disableExternalSkills,
          flags.disableClaudeCodeSkills,
          ctx.directory,
          ctx.worktree,
        )
      }),
    )
    const state = yield* InstanceState.make(
      Effect.fn("Skill.state")(function* () {
        const s: State = { skills: {}, dirs: new Set() }
        // Register the built-in skill BEFORE disk discovery so a user-disk
        // skill with the same name can override it.
        s.skills[CUSTOMIZE_AUDITCODE_SKILL_NAME] = {
          name: CUSTOMIZE_AUDITCODE_SKILL_NAME,
          description: CUSTOMIZE_AUDITCODE_SKILL_DESCRIPTION,
          location: "<built-in>",
          content: CUSTOMIZE_AUDITCODE_SKILL_BODY,
          layer: "builtin",
          source: "built-in",
        }
        yield* loadSkills(s, yield* InstanceState.get(discovered), events)
        return s
      }),
    )

    const get = Effect.fn("Skill.get")(function* (name: string) {
      const s = yield* InstanceState.get(state)
      return s.skills[name]
    })

    const require = Effect.fn("Skill.require")(function* (name: string) {
      const s = yield* InstanceState.get(state)
      const info = s.skills[name]
      if (info) return info
      return yield* new NotFoundError({ name, available: Object.keys(s.skills).toSorted() })
    })

    const all = Effect.fn("Skill.all")(function* () {
      const s = yield* InstanceState.get(state)
      return Object.values(s.skills)
    })

    const dirs = Effect.fn("Skill.dirs")(function* () {
      return (yield* InstanceState.get(discovered)).dirs
    })

    const available = Effect.fn("Skill.available")(function* (agent?: Agent.Info) {
      const s = yield* InstanceState.get(state)
      const list = Object.values(s.skills).toSorted((a, b) => a.name.localeCompare(b.name))
      if (!agent) return list
      return list.filter((skill) => Permission.evaluate("skill", skill.name, agent.permission).action !== "deny")
    })

    return Service.of({ get, require, all, dirs, available })
  }),
)

// Scale the advertised skill set: with hundreds of skills you cannot inject
// every description into the prompt. A skill opts into scoping by declaring
// `tags` — it is then advertised only when one of `relevantTags` (e.g. the
// current engagement phase) matches. Untagged skills are always advertised, so
// this is a no-op until skills adopt tags. Empty `relevantTags` disables scoping.
export function scopeByTags(list: Info[], relevantTags: string[]): Info[] {
  if (relevantTags.length === 0) return list
  const relevant = new Set(relevantTags.map((t) => t.toLowerCase()))
  return list.filter((skill) => {
    if (!skill.tags || skill.tags.length === 0) return true
    return skill.tags.some((tag) => relevant.has(tag.toLowerCase()))
  })
}

export function fmt(list: Info[], opts: { verbose: boolean }) {
  const described = list.filter((skill) => skill.description !== undefined)
  if (described.length === 0) return "No skills are currently available."
  if (opts.verbose) {
    return [
      "<available_skills>",
      ...described
        .toSorted((a, b) => a.name.localeCompare(b.name))
        .flatMap((skill) => [
          "  <skill>",
          `    <name>${skill.name}</name>`,
          `    <description>${skill.description}</description>`,
          `    <location>${escapeHtml(skill.location)}</location>`,
          "  </skill>",
        ]),
      "</available_skills>",
    ].join("\n")
  }

  return [
    "## Available Skills",
    ...described
      .toSorted((a, b) => a.name.localeCompare(b.name))
      .map((skill) => `- **${skill.name}**: ${skill.description}`),
  ].join("\n")
}

export const node = LayerNode.make({
  service: Service,
  layer: layer,
  deps: [Discovery.node, Config.node, EventV2Bridge.node, FSUtil.node, Global.node, RuntimeFlags.node],
})

export * as Skill from "."
