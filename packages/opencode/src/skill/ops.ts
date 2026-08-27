import fs from "fs/promises"
import path from "path"
import { SkillManifest } from "./manifest"

export * as SkillOps from "./ops"

// Filesystem operations behind the `skills` CLI. Plain async (node fs) so they
// are trivially unit-testable with a temp home and reused by the effectCmd
// handlers via Effect.promise. Path layout comes from ./manifest.

export class OpsError extends Error {}

async function exists(p: string): Promise<boolean> {
  return fs
    .access(p)
    .then(() => true)
    .catch(() => false)
}

async function hasSkillFile(dir: string): Promise<boolean> {
  // A valid skill source contains at least one SKILL.md somewhere below `dir`.
  const stack = [dir]
  while (stack.length) {
    const cur = stack.pop()!
    let entries: import("fs").Dirent[]
    try {
      entries = await fs.readdir(cur, { withFileTypes: true })
    } catch {
      continue
    }
    for (const e of entries) {
      if (e.isDirectory()) stack.push(path.join(cur, e.name))
      else if (e.name === "SKILL.md") return true
    }
  }
  return false
}

// Guard: refuse to touch anything outside the managed skills home.
function assertUnderHome(home: string, target: string) {
  const root = SkillManifest.skillsHome(home) + path.sep
  const resolved = path.resolve(target)
  if (!(resolved + path.sep).startsWith(root)) {
    throw new OpsError(`refusing to operate outside the skills home: ${target}`)
  }
}

const SKILL_TEMPLATE = (name: string) => `---
name: ${name}
description: TODO — one sentence on when this skill should be used.
version: 0.1.0
tags: []
---

# ${name}

Document attack techniques, commands, and references here.
`

// Scaffold a new user skill at user/<name>/SKILL.md. Fails if it already exists.
export async function scaffold(home: string, name: string): Promise<string> {
  const dir = path.join(SkillManifest.userDir(home), name)
  const file = path.join(dir, "SKILL.md")
  if (await exists(file)) throw new OpsError(`skill already exists: ${file}`)
  await fs.mkdir(dir, { recursive: true })
  await fs.writeFile(file, SKILL_TEMPLATE(name))
  return file
}

// Copy the directory containing `sourceSkillMd` into user/<destName>, so the
// user layer shadows the bundled/pack origin. `destName` defaults to the source
// skill's directory basename.
export async function fork(home: string, sourceSkillMd: string, destName?: string): Promise<string> {
  if (!(await exists(sourceSkillMd))) throw new OpsError(`source skill not found: ${sourceSkillMd}`)
  const srcDir = path.dirname(sourceSkillMd)
  const name = destName ?? path.basename(srcDir)
  const destDir = path.join(SkillManifest.userDir(home), name)
  if (await exists(destDir)) throw new OpsError(`user skill already exists: ${destDir}`)
  await fs.mkdir(path.dirname(destDir), { recursive: true })
  await fs.cp(srcDir, destDir, { recursive: true })
  return destDir
}

// Remove an installed pack (packs/<id>) and drop its lock entry.
export async function removePack(home: string, id: string): Promise<void> {
  const dir = SkillManifest.packDir(home, id)
  assertUnderHome(home, dir)
  if (!(await exists(dir))) throw new OpsError(`pack not installed: ${id}`)
  await fs.rm(dir, { recursive: true, force: true })
  await removeLockEntry(home, id)
}

// Remove a directory under the skills home (used to remove a user skill dir).
export async function removeDir(home: string, dir: string): Promise<void> {
  assertUnderHome(home, dir)
  if (!(await exists(dir))) throw new OpsError(`not found: ${dir}`)
  await fs.rm(dir, { recursive: true, force: true })
}

// Move a skill directory between the active layer and disabled/ (quarantine).
// `name` is the directory basename under user/ (or disabled/ when re-enabling).
export async function setEnabled(home: string, name: string, enabled: boolean): Promise<string> {
  const from = enabled ? path.join(SkillManifest.disabledDir(home), name) : path.join(SkillManifest.userDir(home), name)
  const to = enabled ? path.join(SkillManifest.userDir(home), name) : path.join(SkillManifest.disabledDir(home), name)
  if (!(await exists(from))) throw new OpsError(`no ${enabled ? "disabled" : "user"} skill directory named ${name}`)
  if (await exists(to)) throw new OpsError(`destination already exists: ${to}`)
  await fs.mkdir(path.dirname(to), { recursive: true })
  await fs.rename(from, to)
  return to
}

// Bring a local directory of skills under management. `as: "pack"` installs it
// as packs/<id> with a .pack.json; `as: "user"` copies it into user/<id>.
export async function importLocal(
  home: string,
  srcDir: string,
  as: "pack" | "user",
  id: string,
): Promise<string> {
  if (!(await exists(srcDir))) throw new OpsError(`directory not found: ${srcDir}`)
  if (!(await hasSkillFile(srcDir))) throw new OpsError(`no SKILL.md found under ${srcDir}`)
  const destDir = as === "pack" ? SkillManifest.packDir(home, id) : path.join(SkillManifest.userDir(home), id)
  if (await exists(destDir)) throw new OpsError(`destination already exists: ${destDir}`)
  await fs.mkdir(path.dirname(destDir), { recursive: true })
  await fs.cp(srcDir, destDir, { recursive: true })
  if (as === "pack") {
    await writePackManifest(home, { id, source: path.resolve(srcDir), installedAt: new Date().toISOString() })
    await upsertLockEntry(home, { id, source: path.resolve(srcDir) })
  }
  return destDir
}

// Atomically place an already-staged pack directory at packs/<id> (used by the
// install flow after a git clone / tarball extract into a temp dir).
export async function installPackFromStaging(
  home: string,
  id: string,
  stagingDir: string,
  source: string,
  version?: string,
): Promise<string> {
  if (!(await hasSkillFile(stagingDir))) throw new OpsError(`no SKILL.md found in downloaded pack: ${source}`)
  const destDir = SkillManifest.packDir(home, id)
  await fs.rm(destDir, { recursive: true, force: true })
  await fs.mkdir(path.dirname(destDir), { recursive: true })
  await fs.cp(stagingDir, destDir, { recursive: true })
  await writePackManifest(home, { id, source, version, installedAt: new Date().toISOString() })
  await upsertLockEntry(home, { id, source, version })
  return destDir
}

// ---- plain-async manifest/lock helpers (mirror SkillManifest, node fs) ------

async function readJson<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(file, "utf8")) as T
  } catch {
    return null
  }
}

async function writeJson(file: string, data: unknown): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, JSON.stringify(data, null, 2))
}

export async function writePackManifest(home: string, manifest: SkillManifest.PackManifest): Promise<void> {
  await writeJson(SkillManifest.packManifestPath(home, manifest.id), manifest)
}

export async function readLock(home: string): Promise<SkillManifest.LockFile> {
  return (await readJson<SkillManifest.LockFile>(SkillManifest.lockPath(home))) ?? { packs: [] }
}

export async function upsertLockEntry(home: string, entry: SkillManifest.LockEntry): Promise<void> {
  const lock = await readLock(home)
  const packs = lock.packs.filter((p) => p.id !== entry.id)
  packs.push(entry)
  packs.sort((a, b) => a.id.localeCompare(b.id))
  await writeJson(SkillManifest.lockPath(home), { packs })
}

export async function removeLockEntry(home: string, id: string): Promise<void> {
  const lock = await readLock(home)
  await writeJson(SkillManifest.lockPath(home), { packs: lock.packs.filter((p) => p.id !== id) })
}

// Extract the `name:` from a SKILL.md's YAML frontmatter (best-effort).
function frontmatterName(content: string): string | undefined {
  const block = content.match(/^---\r?\n([\s\S]*?)\r?\n---/)
  if (!block) return undefined
  const m = block[1].match(/^name:\s*(.+?)\s*$/m)
  return m?.[1]?.replace(/^["']|["']$/g, "")
}

// Locate the SKILL.md of a skill with the given frontmatter name within a layer
// (used by `skills diff` to find a user fork's bundled origin).
export async function findSkillByName(
  home: string,
  layer: "bundled" | "user",
  name: string,
): Promise<string | null> {
  const root = layer === "bundled" ? SkillManifest.bundledDir(home) : SkillManifest.userDir(home)
  const stack = [root]
  while (stack.length) {
    const cur = stack.pop()!
    let entries: import("fs").Dirent[]
    try {
      entries = await fs.readdir(cur, { withFileTypes: true })
    } catch {
      continue
    }
    for (const e of entries) {
      const full = path.join(cur, e.name)
      if (e.isDirectory()) stack.push(full)
      else if (e.name === "SKILL.md") {
        const content = await fs.readFile(full, "utf8").catch(() => "")
        if (frontmatterName(content) === name) return full
      }
    }
  }
  return null
}

export async function listPacks(home: string): Promise<string[]> {
  try {
    const entries = await fs.readdir(SkillManifest.packsDir(home), { withFileTypes: true })
    return entries
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort()
  } catch {
    return []
  }
}
