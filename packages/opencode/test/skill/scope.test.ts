import { describe, expect, test } from "bun:test"
import { Skill } from "../../src/skill"

const mk = (name: string, tags?: string[]): Skill.Info => ({
  name,
  description: name,
  location: `/x/${name}/SKILL.md`,
  content: "",
  ...(tags ? { tags } : {}),
})

describe("scopeByTags", () => {
  const list = [mk("recon-phase", ["recon"]), mk("svc-smb", ["smb", "enumeration"]), mk("svc-notes")]

  test("empty relevant tags disables scoping (returns all)", () => {
    expect(Skill.scopeByTags(list, []).map((s) => s.name)).toEqual(["recon-phase", "svc-smb", "svc-notes"])
  })

  test("untagged skills are always advertised; tagged shown only on match", () => {
    const scoped = Skill.scopeByTags(list, ["recon"]).map((s) => s.name)
    expect(scoped).toContain("recon-phase") // tag matches
    expect(scoped).toContain("svc-notes") // untagged → always
    expect(scoped).not.toContain("svc-smb") // tagged, no match
  })

  test("matching is case-insensitive and any-tag", () => {
    const scoped = Skill.scopeByTags(list, ["ENUMERATION"]).map((s) => s.name)
    expect(scoped).toContain("svc-smb")
    expect(scoped).not.toContain("recon-phase")
  })
})
