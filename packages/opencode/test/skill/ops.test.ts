import { describe, expect, test } from "bun:test"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { SkillOps } from "../../src/skill/ops"
import { SkillManifest } from "../../src/skill/manifest"

async function tmpHome() {
  return fs.mkdtemp(path.join(os.tmpdir(), "pc-ops-"))
}
const exists = (p: string) =>
  fs
    .access(p)
    .then(() => true)
    .catch(() => false)
const doc = (name: string) => `---\nname: ${name}\ndescription: d\n---\n# ${name}\n`

describe("skill ops", () => {
  test("scaffold creates a user skill and refuses to overwrite", async () => {
    const home = await tmpHome()
    const file = await SkillOps.scaffold(home, "my-skill")
    expect(file).toBe(path.join(SkillManifest.userDir(home), "my-skill", "SKILL.md"))
    expect(await exists(file)).toBe(true)
    expect((await fs.readFile(file, "utf8")).includes("name: my-skill")).toBe(true)
    await expect(SkillOps.scaffold(home, "my-skill")).rejects.toThrow(/already exists/)
  })

  test("fork copies a source skill dir into user/", async () => {
    const home = await tmpHome()
    const srcDir = path.join(SkillManifest.bundledDir(home), "services", "smb")
    await fs.mkdir(srcDir, { recursive: true })
    await fs.writeFile(path.join(srcDir, "SKILL.md"), doc("svc-smb"))
    const dest = await SkillOps.fork(home, path.join(srcDir, "SKILL.md"), "smb-fork")
    expect(dest).toBe(path.join(SkillManifest.userDir(home), "smb-fork"))
    expect(await exists(path.join(dest, "SKILL.md"))).toBe(true)
  })

  test("disable then enable moves the directory to/from quarantine", async () => {
    const home = await tmpHome()
    await SkillOps.scaffold(home, "toggle")
    const disabled = await SkillOps.setEnabled(home, "toggle", false)
    expect(disabled).toBe(path.join(SkillManifest.disabledDir(home), "toggle"))
    expect(await exists(path.join(SkillManifest.userDir(home), "toggle"))).toBe(false)
    const enabled = await SkillOps.setEnabled(home, "toggle", true)
    expect(enabled).toBe(path.join(SkillManifest.userDir(home), "toggle"))
    expect(await exists(path.join(SkillManifest.disabledDir(home), "toggle"))).toBe(false)
  })

  test("importLocal as pack writes manifest + lock, and rejects a dir without SKILL.md", async () => {
    const home = await tmpHome()
    const src = await fs.mkdtemp(path.join(os.tmpdir(), "pc-src-"))
    await fs.mkdir(path.join(src, "xss"), { recursive: true })
    await fs.writeFile(path.join(src, "xss", "SKILL.md"), doc("web-xss"))

    const dest = await SkillOps.importLocal(home, src, "pack", "acme-web")
    expect(dest).toBe(SkillManifest.packDir(home, "acme-web"))
    const manifest = JSON.parse(await fs.readFile(SkillManifest.packManifestPath(home, "acme-web"), "utf8"))
    expect(manifest.id).toBe("acme-web")
    const lock = await SkillOps.readLock(home)
    expect(lock.packs.map((p) => p.id)).toContain("acme-web")

    const empty = await fs.mkdtemp(path.join(os.tmpdir(), "pc-empty-"))
    await expect(SkillOps.importLocal(home, empty, "pack", "empty")).rejects.toThrow(/no SKILL\.md/)
  })

  test("removePack deletes the dir and its lock entry", async () => {
    const home = await tmpHome()
    const src = await fs.mkdtemp(path.join(os.tmpdir(), "pc-src2-"))
    await fs.writeFile(path.join(src, "SKILL.md"), doc("p"))
    await SkillOps.importLocal(home, src, "pack", "gone")
    await SkillOps.removePack(home, "gone")
    expect(await exists(SkillManifest.packDir(home, "gone"))).toBe(false)
    expect((await SkillOps.readLock(home)).packs.map((p) => p.id)).not.toContain("gone")
    await expect(SkillOps.removePack(home, "gone")).rejects.toThrow(/not installed/)
  })

  test("removeDir refuses paths outside the skills home", async () => {
    const home = await tmpHome()
    await expect(SkillOps.removeDir(home, "/tmp")).rejects.toThrow(/outside the skills home/)
  })

  test("derivePackId produces filesystem-safe ids", () => {
    expect(SkillManifest.derivePackId("github:acme/web-pack")).toBe("acme-web-pack")
    expect(SkillManifest.derivePackId("https://example.com/team/pack.git")).toBe("team-pack")
    expect(SkillManifest.derivePackId("https://cdn.example.com/skills/index.json")).toBe("cdn.example.com-skills")
  })
})
