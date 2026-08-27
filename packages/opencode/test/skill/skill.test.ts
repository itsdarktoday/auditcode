import { describe, expect } from "bun:test"
import { LayerNode } from "@auditcode/core/effect/layer-node"
import { Effect, Layer } from "effect"
import { Skill } from "../../src/skill"
import { Discovery } from "../../src/skill/discovery"
import { RuntimeFlags } from "../../src/effect/runtime-flags"
import { EventV2Bridge } from "../../src/event-v2-bridge"
import { Config } from "../../src/config/config"
import { CrossSpawnSpawner } from "@auditcode/core/cross-spawn-spawner"
import { FSUtil } from "@auditcode/core/fs-util"
import { Global } from "@auditcode/core/global"
import { provideInstance, provideTmpdirInstance, testInstanceStoreLayer, tmpdir } from "../fixture/fixture"
import { testEffect } from "../lib/effect"
import path from "path"
import fs from "fs/promises"

const node = LayerNode.compile(CrossSpawnSpawner.node)

const it = testEffect(Layer.mergeAll(LayerNode.compile(Skill.node), node, testInstanceStoreLayer))
const itWithoutClaudeCodeSkills = testEffect(
  Layer.mergeAll(
    LayerNode.compile(Skill.node, [[RuntimeFlags.node, RuntimeFlags.layer({ disableClaudeCodeSkills: true })]]),
    node,
    testInstanceStoreLayer,
  ),
)
const itWithoutExternalSkills = testEffect(
  Layer.mergeAll(
    LayerNode.compile(Skill.node, [[RuntimeFlags.node, RuntimeFlags.layer({ disableExternalSkills: true })]]),
    node,
    testInstanceStoreLayer,
  ),
)

async function createGlobalSkill(homeDir: string) {
  const skillDir = path.join(homeDir, ".claude", "skills", "global-test-skill")
  await fs.mkdir(skillDir, { recursive: true })
  await Bun.write(
    path.join(skillDir, "SKILL.md"),
    `---
name: global-test-skill
description: A global skill from ~/.claude/skills for testing.
---

# Global Test Skill

This skill is loaded from the global home directory.
`,
  )
}

function skillDoc(name: string, description: string) {
  return `---
name: ${name}
description: ${description}
---

# ${name}

Body for ${name}.
`
}

// Exercises the global skills home (~/.auditcode/skills) layering. global.home
// is fixed at layer-construction to the ambient OPENCODE_TEST_HOME (preload.ts),
// and withHome can't retroactively change it — so fixtures are written under
// that ambient home and removed afterward. Assertions run in a fresh tmp
// instance (unrelated cwd) so only the global home tree is under test.
// `write` creates <home>/.auditcode/skills/<rel>/SKILL.md.
const withGlobalSkills = (
  create: (write: (rel: string, body: string) => Promise<unknown>) => Promise<unknown>,
  assert: (skill: Skill.Interface) => Effect.Effect<void, any, any>,
) => {
  const skillsRoot = path.join(process.env.OPENCODE_TEST_HOME!, ".auditcode", "skills")
  return Effect.acquireUseRelease(
    Effect.promise(() => create((rel, body) => Bun.write(path.join(skillsRoot, rel, "SKILL.md"), body))),
    () =>
      provideTmpdirInstance(
        () =>
          Effect.gen(function* () {
            const skill = yield* Skill.Service
            yield* assert(skill)
          }),
        { git: true },
      ),
    () => Effect.promise(() => fs.rm(skillsRoot, { recursive: true, force: true })),
  )
}

const withHome = <A, E, R>(home: string, self: Effect.Effect<A, E, R>) =>
  Effect.acquireUseRelease(
    Effect.sync(() => {
      const prev = process.env.OPENCODE_TEST_HOME
      process.env.OPENCODE_TEST_HOME = home
      return prev
    }),
    () => self,
    (prev) =>
      Effect.sync(() => {
        process.env.OPENCODE_TEST_HOME = prev
      }),
  )

describe("skill", () => {
  it.effect("formats verbose locations as XML-safe filesystem paths", () =>
    Effect.sync(() => {
      const output = Skill.fmt(
        [
          {
            name: "tagged-skill",
            description: "A tagged skill.",
            location: "/tmp/plugin.git#v1.3.0/SKILL.md",
            content: "",
          },
          {
            name: "built-in-skill",
            description: "A built-in skill.",
            location: "<built-in>",
            content: "",
          },
        ],
        { verbose: true },
      )

      expect(output).toContain("<location>/tmp/plugin.git#v1.3.0/SKILL.md</location>")
      expect(output).toContain("<location>&lt;built-in&gt;</location>")
      expect(output).not.toContain("file://")
      expect(output).not.toContain("%23")
    }),
  )

  it.live("discovers skills from .auditcode/skill/ directory", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Bun.write(
              path.join(dir, ".auditcode", "skill", "test-skill", "SKILL.md"),
              `---
name: test-skill
description: A test skill for verification.
---

# Test Skill

Instructions here.
`,
            ),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.length).toBe(1)
          const item = list.find((x) => x.name === "test-skill")
          expect(item).toBeDefined()
          expect(item!.description).toBe("A test skill for verification.")
          expect(item!.location).toContain(path.join("skill", "test-skill", "SKILL.md"))
        }),
      { git: true },
    ),
  )

  it.live("returns skill directories from Skill.dirs", () =>
    provideTmpdirInstance(
      (dir) =>
        withHome(
          dir,
          Effect.gen(function* () {
            yield* Effect.promise(() =>
              Bun.write(
                path.join(dir, ".auditcode", "skill", "dir-skill", "SKILL.md"),
                `---
name: dir-skill
description: Skill for dirs test.
---

# Dir Skill
`,
              ),
            )

            const skill = yield* Skill.Service
            const dirs = yield* skill.dirs()
            expect(dirs).toContain(path.join(dir, ".auditcode", "skill", "dir-skill"))
            expect(dirs.length).toBe(1)
          }),
        ),
      { git: true },
    ),
  )

  it.live("discovers multiple skills from .auditcode/skill/ directory", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Promise.all([
              Bun.write(
                path.join(dir, ".auditcode", "skill", "skill-one", "SKILL.md"),
                `---
name: skill-one
description: First test skill.
---

# Skill One
`,
              ),
              Bun.write(
                path.join(dir, ".auditcode", "skill", "skill-two", "SKILL.md"),
                `---
name: skill-two
description: Second test skill.
---

# Skill Two
`,
              ),
            ]),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.length).toBe(2)
          expect(list.find((x) => x.name === "skill-one")).toBeDefined()
          expect(list.find((x) => x.name === "skill-two")).toBeDefined()
        }),
      { git: true },
    ),
  )

  it.live("skips skills with missing frontmatter", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Bun.write(
              path.join(dir, ".auditcode", "skill", "no-frontmatter", "SKILL.md"),
              `# No Frontmatter

Just some content without YAML frontmatter.
`,
            ),
          )

          const skill = yield* Skill.Service
          expect((yield* skill.all()).filter((s) => s.location !== "<built-in>")).toEqual([])
        }),
      { git: true },
    ),
  )

  it.live("discovers skills without descriptions", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Bun.write(
              path.join(dir, ".auditcode", "skill", "manual-skill", "SKILL.md"),
              `---
name: manual-skill
---

# Manual Skill

Instructions here.
`,
            ),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.length).toBe(1)
          const item = list.find((x) => x.name === "manual-skill")
          expect(item).toBeDefined()
          expect(item!.description).toBeUndefined()
          expect(Skill.fmt(list, { verbose: false })).toBe("No skills are currently available.")
          expect(Skill.fmt(list, { verbose: true })).toBe("No skills are currently available.")
        }),
      { git: true },
    ),
  )

  it.live("discovers skills from .claude/skills/ directory", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Bun.write(
              path.join(dir, ".claude", "skills", "claude-skill", "SKILL.md"),
              `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
            ),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.length).toBe(1)
          const item = list.find((x) => x.name === "claude-skill")
          expect(item).toBeDefined()
          expect(item!.location).toContain(path.join(".claude", "skills", "claude-skill", "SKILL.md"))
        }),
      { git: true },
    ),
  )

  it.live("discovers global skills from ~/.claude/skills/ directory", () =>
    Effect.gen(function* () {
      const tmp = yield* Effect.acquireRelease(
        Effect.promise(() => tmpdir({ git: true })),
        (tmp) => Effect.promise(() => tmp[Symbol.asyncDispose]()),
      )

      yield* withHome(
        tmp.path,
        Effect.gen(function* () {
          yield* Effect.promise(() => createGlobalSkill(tmp.path))
          yield* Effect.gen(function* () {
            const skill = yield* Skill.Service
            const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
            expect(list.length).toBe(1)
            expect(list[0].name).toBe("global-test-skill")
            expect(list[0].description).toBe("A global skill from ~/.claude/skills for testing.")
            expect(list[0].location).toContain(path.join(".claude", "skills", "global-test-skill", "SKILL.md"))
          }).pipe(provideInstance(tmp.path))
        }),
      )
    }),
  )

  it.live("returns empty array when no skills exist", () =>
    provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const skill = yield* Skill.Service
          expect((yield* skill.all()).filter((s) => s.location !== "<built-in>")).toEqual([])
        }),
      { git: true },
    ),
  )

  it.live("fails with typed error when requiring a missing skill", () =>
    provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const skill = yield* Skill.Service
          const error = yield* Effect.flip(skill.require("missing-skill"))
          expect(error).toBeInstanceOf(Skill.NotFoundError)
          expect(error._tag).toBe("Skill.NotFoundError")
          expect(error.name).toBe("missing-skill")
          expect(error.message).toContain('Skill "missing-skill" not found.')
        }),
      { git: true },
    ),
  )

  it.effect("exposes tagged expected skill failure classes", () =>
    Effect.sync(() => {
      const invalid = new Skill.InvalidError({ path: "/tmp/SKILL.md", message: "Invalid skill frontmatter" })
      const mismatch = new Skill.NameMismatchError({
        path: "/tmp/SKILL.md",
        expected: "expected-skill",
        actual: "actual-skill",
      })

      expect(invalid).toBeInstanceOf(Skill.InvalidError)
      expect(invalid._tag).toBe("SkillInvalidError")
      expect(mismatch).toBeInstanceOf(Skill.NameMismatchError)
      expect(mismatch._tag).toBe("SkillNameMismatchError")
    }),
  )

  it.live("discovers skills from .agents/skills/ directory", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Bun.write(
              path.join(dir, ".agents", "skills", "agent-skill", "SKILL.md"),
              `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
            ),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.length).toBe(1)
          const item = list.find((x) => x.name === "agent-skill")
          expect(item).toBeDefined()
          expect(item!.location).toContain(path.join(".agents", "skills", "agent-skill", "SKILL.md"))
        }),
      { git: true },
    ),
  )

  it.live("discovers global skills from ~/.agents/skills/ directory", () =>
    Effect.gen(function* () {
      const tmp = yield* Effect.acquireRelease(
        Effect.promise(() => tmpdir({ git: true })),
        (tmp) => Effect.promise(() => tmp[Symbol.asyncDispose]()),
      )

      yield* withHome(
        tmp.path,
        Effect.gen(function* () {
          const skillDir = path.join(tmp.path, ".agents", "skills", "global-agent-skill")
          yield* Effect.promise(() => fs.mkdir(skillDir, { recursive: true }))
          yield* Effect.promise(() =>
            Bun.write(
              path.join(skillDir, "SKILL.md"),
              `---
name: global-agent-skill
description: A global skill from ~/.agents/skills for testing.
---

# Global Agent Skill

This skill is loaded from the global home directory.
`,
            ),
          )

          yield* Effect.gen(function* () {
            const skill = yield* Skill.Service
            const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
            expect(list.length).toBe(1)
            expect(list[0].name).toBe("global-agent-skill")
            expect(list[0].description).toBe("A global skill from ~/.agents/skills for testing.")
            expect(list[0].location).toContain(path.join(".agents", "skills", "global-agent-skill", "SKILL.md"))
          }).pipe(provideInstance(tmp.path))
        }),
      )
    }),
  )

  it.live("discovers skills from both .claude/skills/ and .agents/skills/", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Promise.all([
              Bun.write(
                path.join(dir, ".claude", "skills", "claude-skill", "SKILL.md"),
                `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
              ),
              Bun.write(
                path.join(dir, ".agents", "skills", "agent-skill", "SKILL.md"),
                `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
              ),
            ]),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.length).toBe(2)
          expect(list.find((x) => x.name === "claude-skill")).toBeDefined()
          expect(list.find((x) => x.name === "agent-skill")).toBeDefined()
        }),
      { git: true },
    ),
  )

  itWithoutClaudeCodeSkills.live("skips Claude Code skills when disabled", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Promise.all([
              Bun.write(
                path.join(dir, ".claude", "skills", "claude-skill", "SKILL.md"),
                `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
              ),
              Bun.write(
                path.join(dir, ".agents", "skills", "agent-skill", "SKILL.md"),
                `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
              ),
            ]),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.map((s) => s.name)).toEqual(["agent-skill"])
        }),
      { git: true },
    ),
  )

  itWithoutExternalSkills.live("skips external skill directories when disabled", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Promise.all([
              Bun.write(
                path.join(dir, ".claude", "skills", "claude-skill", "SKILL.md"),
                `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
              ),
              Bun.write(
                path.join(dir, ".agents", "skills", "agent-skill", "SKILL.md"),
                `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
              ),
              Bun.write(
                path.join(dir, ".auditcode", "skill", "auditcode-skill", "SKILL.md"),
                `---
name: auditcode-skill
description: A skill in the .auditcode/skill directory.
---

# OpenCode Skill
`,
              ),
            ]),
          )

          const skill = yield* Skill.Service
          const list = (yield* skill.all()).filter((s) => s.location !== "<built-in>")
          expect(list.map((s) => s.name)).toEqual(["auditcode-skill"])
        }),
      { git: true },
    ),
  )

  it.live("layered precedence: user shadows pack shadows bundled", () =>
    withGlobalSkills(
      (write) =>
        Promise.all([
          write("bundled/dup", skillDoc("dup-skill", "from bundled")),
          write("packs/p1/dup", skillDoc("dup-skill", "from pack")),
          write("user/dup", skillDoc("dup-skill", "from user")),
          write("bundled/only", skillDoc("bundled-only", "unique bundled")),
        ]),
      (skill) =>
        Effect.gen(function* () {
          const all = yield* skill.all()

          const dup = all.filter((s) => s.name === "dup-skill")
          expect(dup.length).toBe(1)
          expect(dup[0].layer).toBe("user")
          expect(dup[0].description).toBe("from user")

          const only = all.find((s) => s.name === "bundled-only")
          expect(only).toBeDefined()
          expect(only!.layer).toBe("bundled")
        }),
    ),
  )

  it.live("skips skills under disabled/", () =>
    withGlobalSkills(
      (write) =>
        Promise.all([
          write("disabled/x", skillDoc("disabled-skill", "nope")),
          write("user/y", skillDoc("enabled-skill", "yes")),
        ]),
      (skill) =>
        Effect.gen(function* () {
          const names = (yield* skill.all()).map((s) => s.name)
          expect(names).toContain("enabled-skill")
          expect(names).not.toContain("disabled-skill")
        }),
    ),
  )

  it.live("legacy flat skills load and are shadowed by the user layer", () =>
    withGlobalSkills(
      (write) =>
        Promise.all([
          // legacy-only skill (pre-layered flat location)
          write("services/ftp", skillDoc("svc-ftp", "legacy flat")),
          // same-named skill present in both legacy flat and user/
          write("services/smb", skillDoc("svc-smb", "legacy flat")),
          write("user/smb", skillDoc("svc-smb", "user override")),
        ]),
      (skill) =>
        Effect.gen(function* () {
          const all = yield* skill.all()

          const ftp = all.find((s) => s.name === "svc-ftp")
          expect(ftp).toBeDefined()
          expect(ftp!.layer).toBe("legacy")

          const smb = all.filter((s) => s.name === "svc-smb")
          expect(smb.length).toBe(1)
          expect(smb[0].layer).toBe("user")
          expect(smb[0].description).toBe("user override")
        }),
    ),
  )

  it.live("parses optional metadata from SKILL.md frontmatter", () =>
    withGlobalSkills(
      (write) =>
        write(
          "user/rich",
          `---
name: rich-skill
description: A skill with full metadata.
id: auditcode.services.rich
version: 2.3.1
author: AuditCode
tags: [smb, windows]
dependencies: [svc-ldap]
requires:
  auditcode: ">=0.2.0"
license: MIT
---

# Rich Skill
`,
        ),
      (skill) =>
        Effect.gen(function* () {
          const item = (yield* skill.all()).find((s) => s.name === "rich-skill")
          expect(item).toBeDefined()
          expect(item!.id).toBe("auditcode.services.rich")
          expect(item!.version).toBe("2.3.1")
          expect(item!.author).toBe("AuditCode")
          expect(item!.tags).toEqual(["smb", "windows"])
          expect(item!.dependencies).toEqual(["svc-ldap"])
          expect(item!.requires?.auditcode).toBe(">=0.2.0")
          expect(item!.license).toBe("MIT")
        }),
    ),
  )

  it.live("properly resolves directories that skills live in", () =>
    provideTmpdirInstance(
      (dir) =>
        Effect.gen(function* () {
          yield* Effect.promise(() =>
            Promise.all([
              Bun.write(
                path.join(dir, ".claude", "skills", "claude-skill", "SKILL.md"),
                `---
name: claude-skill
description: A skill in the .claude/skills directory.
---

# Claude Skill
`,
              ),
              Bun.write(
                path.join(dir, ".agents", "skills", "agent-skill", "SKILL.md"),
                `---
name: agent-skill
description: A skill in the .agents/skills directory.
---

# Agent Skill
`,
              ),
              Bun.write(
                path.join(dir, ".auditcode", "skill", "agent-skill", "SKILL.md"),
                `---
name: auditcode-skill
description: A skill in the .auditcode/skill directory.
---

# OpenCode Skill
`,
              ),
              Bun.write(
                path.join(dir, ".auditcode", "skills", "agent-skill", "SKILL.md"),
                `---
name: auditcode-skill
description: A skill in the .auditcode/skills directory.
---

# OpenCode Skill
`,
              ),
            ]),
          )

          const skill = yield* Skill.Service
          expect((yield* skill.dirs()).length).toBe(4)
        }),
      { git: true },
    ),
  )
})
