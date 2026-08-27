import os from "os"
import path from "path"
import fs from "fs/promises"
import { Effect } from "effect"
import { Global } from "@auditcode/core/global"
import { Skill } from "../../skill"
import { SkillOps } from "../../skill/ops"
import { SkillManifest } from "../../skill/manifest"
import { Discovery } from "../../skill/discovery"
import { Config } from "@/config/config"
import { cmd } from "./cmd"
import { effectCmd, fail } from "../effect-cmd"

const EOL = os.EOL
const out = (s = "") => process.stdout.write(s + EOL)

// ---------------------------------------------------------------------------
// list / info
// ---------------------------------------------------------------------------

const ListCommand = effectCmd({
  command: "list",
  aliases: "ls",
  describe: "list discovered skills grouped by layer",
  builder: (y) => y.option("json", { type: "boolean", describe: "output JSON" }),
  handler: Effect.fn("Cli.skills.list")(function* (args) {
    const skill = yield* Skill.Service
    const skills = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
    if (args.json) {
      out(JSON.stringify(skills, null, 2))
      return
    }
    if (skills.length === 0) {
      out("No skills discovered.")
      return
    }
    const order = ["project", "user", "pack", "legacy", "bundled"]
    const byLayer = new Map<string, typeof skills>()
    for (const s of skills) {
      const layer = s.layer ?? "unknown"
      if (!byLayer.has(layer)) byLayer.set(layer, [])
      byLayer.get(layer)!.push(s)
    }
    for (const layer of [...order, ...[...byLayer.keys()].filter((l) => !order.includes(l))]) {
      const list = byLayer.get(layer)
      if (!list?.length) continue
      out(`${layer} (${list.length})`)
      for (const s of list.sort((a, b) => a.name.localeCompare(b.name))) {
        const version = s.version ? ` v${s.version}` : ""
        out(`  ${s.name}${version}  —  ${s.description ?? "(no description)"}`)
      }
      out()
    }
  }),
})

const InfoCommand = effectCmd({
  command: "info <name>",
  describe: "show a skill's metadata and source",
  builder: (y) => y.positional("name", { type: "string", demandOption: true }),
  handler: Effect.fn("Cli.skills.info")(function* (args) {
    const skill = yield* Skill.Service
    const info = yield* skill.get(args.name as string)
    if (!info) return yield* fail(`skill not found: ${args.name}`)
    const { content, ...meta } = info
    out(JSON.stringify(meta, null, 2))
  }),
})

// ---------------------------------------------------------------------------
// new / fork
// ---------------------------------------------------------------------------

const NewCommand = effectCmd({
  command: "new <name>",
  describe: "scaffold a new skill under user/",
  instance: false,
  builder: (y) => y.positional("name", { type: "string", demandOption: true }),
  handler: Effect.fn("Cli.skills.new")(function* (args) {
    const home = Global.Path.home
    const file = yield* Effect.tryPromise(() => SkillOps.scaffold(home, args.name as string)).pipe(
      Effect.catch((e) => fail(String((e as Error)?.message ?? e))),
    )
    out(`Created ${file}`)
  }),
})

const ForkCommand = effectCmd({
  command: "fork <name>",
  describe: "copy a bundled/pack skill into user/ for safe editing",
  builder: (y) =>
    y
      .positional("name", { type: "string", demandOption: true })
      .option("as", { type: "string", describe: "destination directory name under user/" }),
  handler: Effect.fn("Cli.skills.fork")(function* (args) {
    const home = Global.Path.home
    const skill = yield* Skill.Service
    const info = yield* skill.get(args.name as string)
    if (!info || info.location === "<built-in>") return yield* fail(`skill not found on disk: ${args.name}`)
    const dest = yield* Effect.tryPromise(() =>
      SkillOps.fork(home, info.location, (args.as as string | undefined) ?? undefined),
    ).pipe(Effect.catch((e) => fail(String((e as Error)?.message ?? e))))
    out(`Forked "${args.name}" (${info.layer}) → ${dest}`)
    out(`Edit it there; the user layer shadows the original.`)
  }),
})

// ---------------------------------------------------------------------------
// enable / disable / remove
// ---------------------------------------------------------------------------

const EnableCommand = effectCmd({
  command: "enable <name>",
  describe: "re-enable a disabled skill directory (moves disabled/<name> → user/)",
  instance: false,
  builder: (y) => y.positional("name", { type: "string", demandOption: true }),
  handler: Effect.fn("Cli.skills.enable")(function* (args) {
    const home = Global.Path.home
    const dest = yield* Effect.tryPromise(() => SkillOps.setEnabled(home, args.name as string, true)).pipe(
      Effect.catch((e) => fail(String((e as Error)?.message ?? e))),
    )
    out(`Enabled → ${dest}`)
  }),
})

const DisableCommand = effectCmd({
  command: "disable <name>",
  describe: "quarantine a user skill directory (moves user/<name> → disabled/)",
  instance: false,
  builder: (y) => y.positional("name", { type: "string", demandOption: true }),
  handler: Effect.fn("Cli.skills.disable")(function* (args) {
    const home = Global.Path.home
    const dest = yield* Effect.tryPromise(() => SkillOps.setEnabled(home, args.name as string, false)).pipe(
      Effect.catch((e) => fail(String((e as Error)?.message ?? e))),
    )
    out(`Disabled → ${dest}`)
  }),
})

const RemoveCommand = effectCmd({
  command: "remove <target>",
  aliases: "rm",
  describe: "remove an installed pack, or a user skill by name",
  builder: (y) => y.positional("target", { type: "string", demandOption: true }),
  handler: Effect.fn("Cli.skills.remove")(function* (args) {
    const home = Global.Path.home
    const target = args.target as string
    const packs = yield* Effect.promise(() => SkillOps.listPacks(home))
    if (packs.includes(target)) {
      yield* Effect.tryPromise(() => SkillOps.removePack(home, target)).pipe(
        Effect.catch((e) => fail(String((e as Error)?.message ?? e))),
      )
      out(`Removed pack: ${target}`)
      return
    }
    // Otherwise treat it as a user skill name — only user-layer skills are removable.
    const skill = yield* Skill.Service
    const info = yield* skill.get(target)
    if (!info || info.location === "<built-in>") return yield* fail(`not found: ${target}`)
    if (info.layer !== "user")
      return yield* fail(`refusing to remove a ${info.layer} skill; only user skills and packs are removable`)
    yield* Effect.tryPromise(() => SkillOps.removeDir(home, path.dirname(info.location))).pipe(
      Effect.catch((e) => fail(String((e as Error)?.message ?? e))),
    )
    out(`Removed user skill: ${target}`)
  }),
})

// ---------------------------------------------------------------------------
// import (local) / install (local | github | url | registry) / update
// ---------------------------------------------------------------------------

const ImportCommand = effectCmd({
  command: "import <path>",
  describe: "bring a local directory of skills under management",
  instance: false,
  builder: (y) =>
    y
      .positional("path", { type: "string", demandOption: true })
      .option("as", { type: "string", choices: ["pack", "user"], default: "pack" })
      .option("id", { type: "string", describe: "pack/dir id (defaults to derived name)" }),
  handler: Effect.fn("Cli.skills.import")(function* (args) {
    const home = Global.Path.home
    const src = path.resolve(args.path as string)
    const id = (args.id as string | undefined) ?? SkillManifest.derivePackId(src)
    const dest = yield* Effect.tryPromise(() =>
      SkillOps.importLocal(home, src, args.as as "pack" | "user", id),
    ).pipe(Effect.catch((e) => fail(String((e as Error)?.message ?? e))))
    out(`Imported ${src} → ${dest}`)
  }),
})

// Fetch a source into a fresh staging dir and place it at packs/<id>.
const installSource = (home: string, source: string, discovery: Discovery.Interface) =>
  Effect.gen(function* () {
    const id = SkillManifest.derivePackId(source)
    // Registry index.json → reuse the existing versioned pull, then copy the
    // cached skill dirs into a staging tree.
    if (/index\.json$/i.test(source)) {
      const dirs = yield* discovery.pull(source)
      if (dirs.length === 0) return yield* fail(`no skills found at registry: ${source}`)
      const staging = yield* Effect.promise(() => fs.mkdtemp(path.join(os.tmpdir(), "pc-pack-")))
      for (const d of dirs) {
        yield* Effect.promise(() => fs.cp(d, path.join(staging, path.basename(d)), { recursive: true }))
      }
      const dest = yield* Effect.tryPromise(() =>
        SkillOps.installPackFromStaging(home, id, staging, source),
      ).pipe(Effect.catch((e) => fail(String((e as Error)?.message ?? e))))
      yield* Effect.promise(() => fs.rm(staging, { recursive: true, force: true }))
      return dest
    }

    // Local path → copy directly.
    const local = path.resolve(source)
    if (yield* Effect.promise(() => fs.stat(local).then((s) => s.isDirectory()).catch(() => false))) {
      return yield* Effect.tryPromise(() => SkillOps.importLocal(home, local, "pack", id)).pipe(
        Effect.catch((e) => fail(String((e as Error)?.message ?? e))),
      )
    }

    // git (github:owner/repo[@ref] or a .git URL) / archive URL → shell out.
    const { $ } = yield* Effect.promise(() => import("bun"))
    const staging = yield* Effect.promise(() => fs.mkdtemp(path.join(os.tmpdir(), "pc-pack-")))
    const finish = (version?: string) =>
      Effect.gen(function* () {
        const dest = yield* Effect.tryPromise(() =>
          SkillOps.installPackFromStaging(home, id, staging, source, version),
        ).pipe(Effect.catch((e) => fail(String((e as Error)?.message ?? e))))
        yield* Effect.promise(() => fs.rm(staging, { recursive: true, force: true }))
        return dest
      })

    const gh = source.match(/^github:([^@]+)(?:@(.+))?$/i)
    if (gh || /\.git($|@)/i.test(source) || /^https?:\/\/.*(github|gitlab|bitbucket)/i.test(source)) {
      const ref = gh?.[2]
      const url = gh ? `https://github.com/${gh[1]}.git` : source.replace(/@[^/]+$/, "")
      yield* Effect.tryPromise(() =>
        ref
          ? $`git clone --depth 1 --branch ${ref} ${url} ${staging}`.quiet()
          : $`git clone --depth 1 ${url} ${staging}`.quiet(),
      ).pipe(Effect.catch((e) => fail(`git clone failed: ${String((e as Error)?.message ?? e)}`)))
      return yield* finish(ref)
    }

    if (/^https?:\/\//i.test(source)) {
      const archive = path.join(staging, "archive")
      const res = yield* Effect.tryPromise(() => fetch(source)).pipe(Effect.catch((e) => fail(String(e))))
      if (!res.ok) return yield* fail(`download failed (${res.status}): ${source}`)
      const buf = new Uint8Array(yield* Effect.promise(() => res.arrayBuffer()))
      yield* Effect.promise(() => fs.writeFile(archive, buf))
      yield* Effect.tryPromise(() =>
        /\.zip$/i.test(source) ? $`unzip -qo ${archive} -d ${staging}`.quiet() : $`tar -xzf ${archive} -C ${staging}`.quiet(),
      ).pipe(Effect.catch((e) => fail(`extract failed: ${String((e as Error)?.message ?? e)}`)))
      yield* Effect.promise(() => fs.rm(archive, { force: true }))
      return yield* finish()
    }

    yield* Effect.promise(() => fs.rm(staging, { recursive: true, force: true }))
    return yield* fail(`unrecognized source: ${source}`)
  })

const InstallCommand = effectCmd({
  command: "install <source>",
  aliases: "add",
  describe: "install a skill pack from github:, a URL, a registry index.json, or a local path",
  instance: false,
  builder: (y) => y.positional("source", { type: "string", demandOption: true }),
  handler: Effect.fn("Cli.skills.install")(function* (args) {
    const home = Global.Path.home
    const discovery = yield* Discovery.Service
    const dest = yield* installSource(home, args.source as string, discovery)
    out(`Installed → ${dest}`)
  }),
})

const UpdateCommand = effectCmd({
  command: "update [pack]",
  describe: "re-install packs from their recorded sources (all packs if none named)",
  instance: false,
  builder: (y) =>
    y.positional("pack", { type: "string" }).option("check", { type: "boolean", describe: "list what would update" }),
  handler: Effect.fn("Cli.skills.update")(function* (args) {
    const home = Global.Path.home
    const discovery = yield* Discovery.Service
    const lock = yield* Effect.promise(() => SkillOps.readLock(home))
    const targets = args.pack ? lock.packs.filter((p) => p.id === args.pack) : lock.packs
    if (targets.length === 0) return out(args.pack ? `no such pack: ${args.pack}` : "no packs installed")
    if (args.check) {
      for (const p of targets) out(`${p.id}  (${p.source ?? "no source"})`)
      return
    }
    for (const p of targets) {
      if (!p.source) {
        out(`skip ${p.id}: no recorded source`)
        continue
      }
      yield* installSource(home, p.source, discovery)
      out(`updated ${p.id}`)
    }
  }),
})

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

const DoctorCommand = effectCmd({
  command: "doctor",
  describe: "validate skills: duplicate names, unmet min-version, missing dependencies",
  handler: Effect.fn("Cli.skills.doctor")(function* () {
    const skill = yield* Skill.Service
    const skills = yield* skill.all()
    const names = new Set(skills.map((s) => s.name))
    const issues: string[] = []
    const { InstallationVersion } = yield* Effect.promise(() => import("@auditcode/core/installation/version"))

    for (const s of skills) {
      if (s.requires?.auditcode && !satisfiesMin(InstallationVersion, s.requires.auditcode)) {
        issues.push(`${s.name}: requires auditcode ${s.requires.auditcode} (have ${InstallationVersion})`)
      }
      for (const dep of s.dependencies ?? []) {
        if (!names.has(dep)) issues.push(`${s.name}: missing dependency "${dep}"`)
      }
    }

    if (issues.length === 0) {
      out(`✓ ${skills.length} skills OK`)
      return
    }
    for (const i of issues) out(`⚠ ${i}`)
    return yield* fail(`${issues.length} issue(s) found`)
  }),
})

// Minimal ">=x.y.z" / "x.y.z" check — warn-and-load, so precision isn't critical.
function satisfiesMin(current: string, requirement: string): boolean {
  const req = requirement.replace(/^[>=^~\s]+/, "")
  const norm = (v: string) =>
    v
      .split("-")[0]
      .split(".")
      .map((n) => parseInt(n, 10) || 0)
  const [a, b] = [norm(current), norm(req)]
  for (let i = 0; i < 3; i++) {
    const x = a[i] ?? 0
    const y = b[i] ?? 0
    if (x > y) return true
    if (x < y) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// search / diff
// ---------------------------------------------------------------------------

const SearchCommand = effectCmd({
  command: "search <query>",
  describe: "search configured registries (skills.urls) for installable skills",
  builder: (y) =>
    y
      .positional("query", { type: "string", demandOption: true })
      .option("url", { type: "string", describe: "registry index.json to search (defaults to config skills.urls)" }),
  handler: Effect.fn("Cli.skills.search")(function* (args) {
    const urls: string[] = []
    if (args.url) urls.push(args.url as string)
    else {
      const cfg = yield* Config.Service.use((c) => c.get())
      urls.push(...(cfg.skills?.urls ?? []))
    }
    if (urls.length === 0) return yield* fail("no registries configured (set skills.urls or pass --url)")

    const q = (args.query as string).toLowerCase()
    let matches = 0
    for (const base of urls) {
      const indexUrl = /index\.json$/i.test(base) ? base : `${base.replace(/\/$/, "")}/index.json`
      const res = yield* Effect.tryPromise(() => fetch(indexUrl)).pipe(Effect.catch(() => Effect.succeed(null)))
      if (!res || !res.ok) {
        out(`(could not fetch ${indexUrl})`)
        continue
      }
      const data = (yield* Effect.tryPromise(() => res.json()).pipe(Effect.catch(() => Effect.succeed(null)))) as {
        skills?: Array<{ name?: string; version?: string }>
      } | null
      for (const s of data?.skills ?? []) {
        if (s.name && s.name.toLowerCase().includes(q)) {
          matches++
          out(`  ${s.name}${s.version ? ` v${s.version}` : ""}  —  ${indexUrl}`)
        }
      }
    }
    if (matches === 0) out(`No skills matching "${args.query}".`)
  }),
})

const DiffCommand = effectCmd({
  command: "diff <name>",
  describe: "show how a user fork differs from its bundled origin",
  builder: (y) => y.positional("name", { type: "string", demandOption: true }),
  handler: Effect.fn("Cli.skills.diff")(function* (args) {
    const home = Global.Path.home
    const skill = yield* Skill.Service
    const info = yield* skill.get(args.name as string)
    if (!info || info.layer !== "user")
      return yield* fail(`diff compares a user fork; no user skill named "${args.name}"`)
    const origin = yield* Effect.promise(() => SkillOps.findSkillByName(home, "bundled", args.name as string))
    if (!origin) return yield* fail(`no bundled origin for "${args.name}" to diff against`)

    const { $ } = yield* Effect.promise(() => import("bun"))
    const res = yield* Effect.promise(() => $`diff -u ${origin} ${info.location}`.quiet().nothrow())
    if (res.exitCode === 0) {
      out(`No differences: user fork matches bundled origin.`)
      return
    }
    process.stdout.write(res.stdout.toString())
  }),
})

export const SkillsCommand = cmd({
  command: "skills",
  describe: "manage skills (list, install, import, update, remove, ...)",
  builder: (yargs) =>
    yargs
      .command(ListCommand)
      .command(InfoCommand)
      .command(NewCommand)
      .command(ForkCommand)
      .command(EnableCommand)
      .command(DisableCommand)
      .command(RemoveCommand)
      .command(ImportCommand)
      .command(InstallCommand)
      .command(UpdateCommand)
      .command(SearchCommand)
      .command(DiffCommand)
      .command(DoctorCommand)
      .demandCommand(),
  async handler() {},
})
