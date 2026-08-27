import path from "path"
import { Effect, Option, Schema } from "effect"
import { FSUtil } from "@auditcode/core/fs-util"

export * as SkillManifest from "./manifest"

// ---------------------------------------------------------------------------
// Layout — physical separation of provenance under ~/.auditcode/skills.
// bundled/ (release-owned) < packs/ (imported) < user/ (user-owned). Updates
// only ever rewrite the layer they own; user/ and packs/<id> survive refreshes.
// ---------------------------------------------------------------------------

export function skillsHome(home: string) {
  return path.join(home, ".auditcode", "skills")
}
export function bundledDir(home: string) {
  return path.join(skillsHome(home), "bundled")
}
export function packsDir(home: string) {
  return path.join(skillsHome(home), "packs")
}
export function userDir(home: string) {
  return path.join(skillsHome(home), "user")
}
export function disabledDir(home: string) {
  return path.join(skillsHome(home), "disabled")
}
export function lockPath(home: string) {
  return path.join(skillsHome(home), "skills.lock.json")
}
export function packDir(home: string, id: string) {
  return path.join(packsDir(home), id)
}
export function packManifestPath(home: string, id: string) {
  return path.join(packDir(home, id), ".pack.json")
}
export function bundledManifestPath(home: string) {
  return path.join(bundledDir(home), ".manifest.json")
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

// bundled/.manifest.json — written by src/skill/bundled.ts when seeding.
export const BundledManifest = Schema.Struct({
  bundleVersion: Schema.String,
  files: Schema.optional(Schema.Record(Schema.String, Schema.String)),
})
export type BundledManifest = Schema.Schema.Type<typeof BundledManifest>

// packs/<id>/.pack.json — one per installed community/imported pack.
export const PackManifest = Schema.Struct({
  id: Schema.String,
  version: Schema.optional(Schema.String),
  source: Schema.optional(Schema.String),
  skills: Schema.optional(Schema.Array(Schema.String)),
  checksum: Schema.optional(Schema.String),
  installedAt: Schema.optional(Schema.String),
})
export type PackManifest = Schema.Schema.Type<typeof PackManifest>

// skills.lock.json — pins installed packs for reproducible team setups.
export const LockEntry = Schema.Struct({
  id: Schema.String,
  version: Schema.optional(Schema.String),
  source: Schema.optional(Schema.String),
  checksum: Schema.optional(Schema.String),
})
export type LockEntry = Schema.Schema.Type<typeof LockEntry>

export const LockFile = Schema.Struct({
  packs: Schema.Array(LockEntry),
})
export type LockFile = Schema.Schema.Type<typeof LockFile>

// ---------------------------------------------------------------------------
// IO helpers — tolerant reads (missing/corrupt → sensible empty default),
// pretty-printed writes. FSUtil is passed explicitly (see bundled.ts).
// ---------------------------------------------------------------------------

const readRaw = (fsys: FSUtil.Interface, file: string) =>
  Effect.gen(function* () {
    const raw = yield* fsys.readFileStringSafe(file).pipe(Effect.catch(() => Effect.succeed(undefined)))
    if (!raw) return undefined
    try {
      return JSON.parse(raw) as unknown
    } catch {
      return undefined
    }
  })

const writeJson = (fsys: FSUtil.Interface, file: string, data: unknown) =>
  fsys.writeWithDirs(file, JSON.stringify(data, null, 2))

export const readLock = (fsys: FSUtil.Interface, home: string): Effect.Effect<LockFile> =>
  Effect.gen(function* () {
    const parsed = yield* readRaw(fsys, lockPath(home))
    if (parsed === undefined) return { packs: [] }
    return Schema.decodeUnknownOption(LockFile)(parsed).pipe(Option.getOrElse(() => ({ packs: [] }) as LockFile))
  })

export const writeLock = (fsys: FSUtil.Interface, home: string, lock: LockFile) =>
  writeJson(fsys, lockPath(home), lock)

// Upsert a pack entry (dedup by id) and persist the lockfile.
export const upsertLockEntry = (fsys: FSUtil.Interface, home: string, entry: LockEntry) =>
  Effect.gen(function* () {
    const lock = yield* readLock(fsys, home)
    const packs = lock.packs.filter((p) => p.id !== entry.id)
    packs.push(entry)
    packs.sort((a, b) => a.id.localeCompare(b.id))
    yield* writeLock(fsys, home, { packs })
  })

export const removeLockEntry = (fsys: FSUtil.Interface, home: string, id: string) =>
  Effect.gen(function* () {
    const lock = yield* readLock(fsys, home)
    yield* writeLock(fsys, home, { packs: lock.packs.filter((p) => p.id !== id) })
  })

export const readPackManifest = (
  fsys: FSUtil.Interface,
  home: string,
  id: string,
): Effect.Effect<PackManifest | null> =>
  Effect.gen(function* () {
    const parsed = yield* readRaw(fsys, packManifestPath(home, id))
    if (parsed === undefined) return null
    return Schema.decodeUnknownOption(PackManifest)(parsed).pipe(Option.getOrNull)
  })

export const writePackManifest = (fsys: FSUtil.Interface, home: string, manifest: PackManifest) =>
  writeJson(fsys, packManifestPath(home, manifest.id), manifest)

export const readBundledManifest = (fsys: FSUtil.Interface, home: string): Effect.Effect<BundledManifest | null> =>
  Effect.gen(function* () {
    const parsed = yield* readRaw(fsys, bundledManifestPath(home))
    if (parsed === undefined) return null
    return Schema.decodeUnknownOption(BundledManifest)(parsed).pipe(Option.getOrNull)
  })

// Derive a filesystem-safe pack id from an install source (github:u/r, URL, path).
export function derivePackId(source: string): string {
  let base = source.trim()
  base = base.replace(/^github:/i, "").replace(/^https?:\/\//i, "")
  base = base.replace(/\.git$/i, "").replace(/@.*$/, "")
  base = base.replace(/\/(index\.json|.*\.tar\.gz|.*\.tgz|.*\.zip)$/i, "")
  const parts = base.split(/[\/\\]/).filter(Boolean)
  const tail = parts.slice(-2).join("-") || parts.join("-") || "pack"
  return (
    tail
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64) || "pack"
  )
}
