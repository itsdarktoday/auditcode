import { describe, expect } from "bun:test"
import { LayerNode } from "@auditcode/core/effect/layer-node"
import { FSUtil } from "@auditcode/core/fs-util"
import { Global } from "@auditcode/core/global"
import { Effect } from "effect"
import { BundledSkills } from "../../src/skill/bundled"
import { testEffect } from "../lib/effect"
import fs from "fs/promises"
import os from "os"
import path from "path"

const it = testEffect(LayerNode.compile(FSUtil.node))

// Build a throwaway directory that stands in for the binary-embedded bundle:
// returns a { relPath -> absolute-path } map suitable for EmbeddedBundle.files.
async function mkEmbedded(files: Record<string, string>) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "pc-embed-"))
  const map: Record<string, string> = {}
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(dir, rel)
    await fs.mkdir(path.dirname(p), { recursive: true })
    await fs.writeFile(p, body)
    map[rel] = p
  }
  return map
}

const read = (p: string) => Effect.promise(() => fs.readFile(p, "utf8"))
const exists = (p: string) =>
  Effect.promise(() =>
    fs
      .access(p)
      .then(() => true)
      .catch(() => false),
  )

describe("bundled skill seeding", () => {
  it.live("seeds bundled/, gates re-seed on version, replaces wholesale, never touches user/", () =>
    Effect.gen(function* () {
      const fsys = yield* FSUtil.Service
      const home = yield* Effect.promise(() => fs.mkdtemp(path.join(os.tmpdir(), "pc-home-")))
      const global = Global.make({ home })
      const bundledDir = path.join(home, ".auditcode", "skills", "bundled")
      const smb = path.join(bundledDir, "services", "smb", "SKILL.md")
      const ftp = path.join(bundledDir, "services", "ftp", "SKILL.md")

      // A pre-existing user skill must survive every seed.
      const userSkill = path.join(home, ".auditcode", "skills", "user", "mine", "SKILL.md")
      yield* Effect.promise(() => fs.mkdir(path.dirname(userSkill), { recursive: true }))
      yield* Effect.promise(() => fs.writeFile(userSkill, "user content"))

      // Initial seed.
      yield* BundledSkills.apply(fsys, global, {
        version: "1.0.0",
        files: yield* Effect.promise(() => mkEmbedded({ "services/smb/SKILL.md": "v1 smb" })),
      })
      expect(yield* read(smb)).toBe("v1 smb")
      const manifest = JSON.parse(yield* read(path.join(bundledDir, ".manifest.json")))
      expect(manifest.bundleVersion).toBe("1.0.0")
      expect(typeof manifest.files["services/smb/SKILL.md"]).toBe("string")

      // Same version, different content → version gate blocks re-seed.
      yield* BundledSkills.apply(fsys, global, {
        version: "1.0.0",
        files: yield* Effect.promise(() => mkEmbedded({ "services/smb/SKILL.md": "v2 smb" })),
      })
      expect(yield* read(smb)).toBe("v1 smb")

      // Version bump → wholesale replace: ftp appears, stale smb is gone.
      yield* BundledSkills.apply(fsys, global, {
        version: "2.0.0",
        files: yield* Effect.promise(() => mkEmbedded({ "services/ftp/SKILL.md": "v3 ftp" })),
      })
      expect(yield* read(ftp)).toBe("v3 ftp")
      expect(yield* exists(smb)).toBe(false)

      // user/ untouched throughout.
      expect(yield* read(userSkill)).toBe("user content")
    }),
  )
})
