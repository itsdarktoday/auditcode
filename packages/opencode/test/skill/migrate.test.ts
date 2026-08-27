import { describe, expect, test } from "bun:test"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { createHash } from "crypto"
import { SkillMigrate } from "../../src/skill/migrate"
import { SkillManifest } from "../../src/skill/manifest"

const exists = (p: string) =>
  fs
    .access(p)
    .then(() => true)
    .catch(() => false)
const doc = (name: string, extra = "") => `---\nname: ${name}\ndescription: d\n${extra}---\n# ${name}\n`
const sha = (s: string) => createHash("sha256").update(Buffer.from(s)).digest("hex")

async function tmpHome() {
  return fs.mkdtemp(path.join(os.tmpdir(), "pc-mig-"))
}

describe("legacy layout migration", () => {
  test("classifies pristine→drop, modified→user, unknown→user; backs up; writes report", async () => {
    const home = await tmpHome()
    const root = SkillManifest.skillsHome(home)

    // Legacy flat skills.
    const pristineBody = doc("svc-smb")
    const modifiedBody = doc("svc-ftp", "# customized\n")
    await fs.mkdir(path.join(root, "services", "smb"), { recursive: true })
    await fs.writeFile(path.join(root, "services", "smb", "SKILL.md"), pristineBody)
    await fs.mkdir(path.join(root, "services", "ftp"), { recursive: true })
    await fs.writeFile(path.join(root, "services", "ftp", "SKILL.md"), modifiedBody)
    await fs.mkdir(path.join(root, "playbooks", "custom"), { recursive: true })
    await fs.writeFile(path.join(root, "playbooks", "custom", "SKILL.md"), doc("my-playbook"))

    // Bundled manifest: smb is pristine (checksum matches), ftp differs (bundle
    // ships a different version), custom is unknown (not in bundle).
    await fs.mkdir(SkillManifest.bundledDir(home), { recursive: true })
    await fs.writeFile(
      SkillManifest.bundledManifestPath(home),
      JSON.stringify({
        bundleVersion: "1.0.0",
        files: {
          "services/smb/SKILL.md": sha(pristineBody),
          "services/ftp/SKILL.md": sha("different bundled ftp"),
        },
      }),
    )

    const report = await SkillMigrate.run(home)
    expect(report).not.toBeNull()

    // Pristine dropped, modified + unknown relocated to user/.
    expect(report!.dropped).toContain("services/smb/SKILL.md")
    expect(await exists(path.join(root, "services", "smb"))).toBe(false)
    expect(await exists(path.join(SkillManifest.userDir(home), "ftp", "SKILL.md"))).toBe(true)
    expect(await exists(path.join(SkillManifest.userDir(home), "custom", "SKILL.md"))).toBe(true)
    // Modified content preserved verbatim.
    expect(await fs.readFile(path.join(SkillManifest.userDir(home), "ftp", "SKILL.md"), "utf8")).toBe(modifiedBody)

    // Backup holds the originals; report written.
    expect(await exists(path.join(report!.backupDir, "services", "ftp", "SKILL.md"))).toBe(true)
    expect(await exists(path.join(root, "MIGRATION-REPORT.md"))).toBe(true)

    // Idempotent: a second run finds no legacy files.
    expect(await SkillMigrate.run(home)).toBeNull()
  })

  test("returns null when there is no legacy layout", async () => {
    const home = await tmpHome()
    await fs.mkdir(path.join(SkillManifest.userDir(home), "mine"), { recursive: true })
    await fs.writeFile(path.join(SkillManifest.userDir(home), "mine", "SKILL.md"), doc("mine"))
    await fs.mkdir(path.join(SkillManifest.bundledDir(home), "services", "smb"), { recursive: true })
    await fs.writeFile(path.join(SkillManifest.bundledDir(home), "services", "smb", "SKILL.md"), doc("svc-smb"))
    // Only managed layer dirs present → nothing to migrate.
    expect(await SkillMigrate.run(home)).toBeNull()
  })
})
