import fs from "fs/promises"
import path from "path"
import { createHash } from "crypto"
import { SkillManifest } from "./manifest"

export * as SkillMigrate from "./migrate"

// One-time migration from the pre-layered flat layout (SKILL.md files directly
// under ~/.auditcode/skills/{phases,services,playbooks,...}) to the layered
// layout. Non-destructive: everything is backed up first, pristine bundled
// copies are dropped (reseeded into bundled/), and modified/unknown skills are
// relocated into user/ so customizations survive. Idempotent — after the first
// run no legacy files remain, so it is a no-op thereafter.

export type MigrationReport = {
  backupDir: string
  dropped: string[] // relPath — pristine bundled copies, safe to drop
  movedToUser: string[] // "relPath -> user/<name>" — preserved user content
  reportPath: string
}

const MANAGED = new Set(["bundled", "packs", "user", "disabled"])

async function exists(p: string): Promise<boolean> {
  return fs
    .access(p)
    .then(() => true)
    .catch(() => false)
}

function sha256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex")
}

// SKILL.md files under the skills home that are NOT inside a managed layer dir.
async function findLegacy(root: string): Promise<string[]> {
  const found: string[] = []
  async function walk(dir: string, top: boolean) {
    let entries: import("fs").Dirent[]
    try {
      entries = await fs.readdir(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const full = path.join(dir, e.name)
      if (e.isDirectory()) {
        if (top && MANAGED.has(e.name)) continue // skip layered dirs
        await walk(full, false)
      } else if (e.name === "SKILL.md") {
        found.push(full)
      }
    }
  }
  await walk(root, true)
  return found
}

async function removeEmptyParents(root: string, startDir: string) {
  let dir = startDir
  while (dir.startsWith(root) && dir !== root) {
    try {
      const entries = await fs.readdir(dir)
      if (entries.length > 0) break
      await fs.rmdir(dir)
    } catch {
      break
    }
    dir = path.dirname(dir)
  }
}

export async function run(home: string): Promise<MigrationReport | null> {
  const root = SkillManifest.skillsHome(home)
  if (!(await exists(root))) return null

  const legacy = await findLegacy(root)
  if (legacy.length === 0) return null

  const manifest = await readBundledManifestJson(home)
  const version = manifest?.bundleVersion ?? "unknown"
  const backupDir = path.join(home, ".auditcode", `skills.bak-${version}`)
  const userRoot = SkillManifest.userDir(home)

  const dropped: string[] = []
  const movedToUser: string[] = []

  for (const skillMd of legacy) {
    const rel = path.relative(root, skillMd) // e.g. services/smb/SKILL.md
    const relDir = path.dirname(rel) // e.g. services/smb
    const srcDir = path.dirname(skillMd)

    // Back up the whole skill dir before touching it.
    const backup = path.join(backupDir, relDir)
    await fs.mkdir(path.dirname(backup), { recursive: true })
    await fs.cp(srcDir, backup, { recursive: true }).catch(() => {})

    const actual = sha256(await fs.readFile(skillMd))
    const expected = manifest?.files?.[rel]

    if (expected && expected === actual) {
      // Pristine bundled copy → drop (bundled/ already holds the seeded copy).
      await fs.rm(srcDir, { recursive: true, force: true })
      dropped.push(rel)
    } else {
      // Modified bundled skill or user-authored → preserve in user/.
      const base = path.basename(relDir) || "skill"
      let destName = base
      let dest = path.join(userRoot, destName)
      let n = 1
      while (await exists(dest)) dest = path.join(userRoot, `${base}-${n++}`)
      await fs.mkdir(userRoot, { recursive: true })
      await fs.cp(srcDir, dest, { recursive: true })
      await fs.rm(srcDir, { recursive: true, force: true })
      movedToUser.push(`${rel} -> user/${path.basename(dest)}`)
    }
    await removeEmptyParents(root, path.dirname(srcDir))
  }

  const reportPath = path.join(root, "MIGRATION-REPORT.md")
  await fs.writeFile(reportPath, renderReport({ version, backupDir, dropped, movedToUser }))

  return { backupDir, dropped, movedToUser, reportPath }
}

async function readBundledManifestJson(
  home: string,
): Promise<{ bundleVersion?: string; files?: Record<string, string> } | null> {
  try {
    return JSON.parse(await fs.readFile(SkillManifest.bundledManifestPath(home), "utf8"))
  } catch {
    return null
  }
}

function renderReport(input: {
  version: string
  backupDir: string
  dropped: string[]
  movedToUser: string[]
}): string {
  const lines = [
    `# Skills layout migration`,
    ``,
    `The flat \`~/.auditcode/skills\` layout was migrated to the layered layout`,
    `(bundled/ · packs/ · user/). A full backup was taken first — nothing was lost.`,
    ``,
    `- Bundle version: \`${input.version}\``,
    `- Backup: \`${input.backupDir}\``,
    ``,
    `## Preserved in user/ (${input.movedToUser.length})`,
    `Modified or user-authored skills — these now shadow any bundled skill of the same name.`,
    ``,
    ...(input.movedToUser.length ? input.movedToUser.map((m) => `- ${m}`) : ["- (none)"]),
    ``,
    `## Dropped (${input.dropped.length})`,
    `Pristine copies of bundled skills — identical to what ships in the binary, now served from bundled/.`,
    ``,
    ...(input.dropped.length ? input.dropped.map((d) => `- ${d}`) : ["- (none)"]),
    ``,
  ]
  return lines.join("\n")
}
