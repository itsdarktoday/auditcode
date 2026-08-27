export * as BuiltInTools from "./builtins"

import { makeLocationNode } from "../effect/app-node"
import { Layer } from "effect"
import { BashTool } from "./bash"
import { GlobTool } from "./glob"
import { GrepTool } from "./grep"
import { QuestionTool } from "./question"
import { ReadTool } from "./read"
import { SkillTool } from "./skill"
import { WebFetchTool } from "./webfetch"
import { WebSearchTool } from "./websearch"
import { WriteTool } from "./write"

export const node = makeLocationNode({
  name: "built-in-tools",
  layer: Layer.empty,
  deps: [
    BashTool.node,
    GlobTool.node,
    GrepTool.node,
    QuestionTool.node,
    ReadTool.node,
    SkillTool.node,
    WebFetchTool.node,
    WebSearchTool.node,
    WriteTool.node,
  ],
})
