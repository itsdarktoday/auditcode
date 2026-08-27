/// <reference path="../markdown.d.ts" />

export * as SkillPlugin from "./skill"

import { define } from "./internal"
import { Effect } from "effect"
import { AbsolutePath } from "../schema"
import { SkillV2 } from "../skill"
import customizeAuditcodeContent from "./skill/customize-auditcode.md" with { type: "text" }

export const CustomizeAuditcodeContent = customizeAuditcodeContent

export const Plugin = define({
  id: "skill",
  effect: Effect.fn(function* (ctx) {
    yield* ctx.skill.transform((draft) => {
      draft.source(
        SkillV2.EmbeddedSource.make({
          type: "embedded",
          skill: SkillV2.Info.make({
            name: "customize-auditcode",
            description:
              "Use ONLY when the user is editing or creating auditcode's own configuration: auditcode.json, auditcode.jsonc, files under .auditcode/, or files under ~/.config/auditcode/. Also use when creating or fixing auditcode agents, subagents, commands, skills, plugins, MCP servers, or permission rules. Do not use for the user's own application code, or for any project that is not configuring auditcode itself.",
            location: AbsolutePath.make("/builtin/customize-auditcode.md"),
            content: CustomizeAuditcodeContent,
          }),
        }),
      )
    })
  }),
})
