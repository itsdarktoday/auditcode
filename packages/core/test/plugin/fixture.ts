import { AgentV2 } from "@auditcode/core/agent"
import { AISDK } from "@auditcode/core/aisdk"
import { Catalog } from "@auditcode/core/catalog"
import { CommandV2 } from "@auditcode/core/command"
import { Credential } from "@auditcode/core/credential"
import { AppNodeBuilder } from "@auditcode/core/effect/app-node-builder"
import { LayerNodePlatform } from "@auditcode/core/effect/app-node-platform"
import { LayerNode } from "@auditcode/core/effect/layer-node"
import { EventV2 } from "@auditcode/core/event"
import { FileSystem } from "@auditcode/core/filesystem"
import { FSUtil } from "@auditcode/core/fs-util"
import { Integration } from "@auditcode/core/integration"
import { Location } from "@auditcode/core/location"
import { Npm } from "@auditcode/core/npm"
import { PluginV2 } from "@auditcode/core/plugin"
import { Reference } from "@auditcode/core/reference"
import { SkillV2 } from "@auditcode/core/skill"
import { Effect, Layer } from "effect"
import { tempLocationLayer } from "../fixture/location"

const npmLayer = Layer.succeed(
  Npm.Service,
  Npm.Service.of({
    add: () => Effect.succeed({ directory: "", entrypoint: undefined }),
    install: () => Effect.void,
    which: () => Effect.succeed(undefined),
  }),
)

export const PluginTestLayer = AppNodeBuilder.build(
  LayerNode.group([
    FileSystem.node,
    FSUtil.node,
    Location.node,
    Npm.node,
    Credential.node,
    EventV2.node,
    LayerNodePlatform.httpClient,
    PluginV2.node,
    AgentV2.node,
    AISDK.node,
    Catalog.node,
    CommandV2.node,
    Integration.node,
    Reference.node,
    SkillV2.node,
  ]),
  [
    [Location.node, tempLocationLayer],
    [Npm.node, npmLayer],
  ],
)
