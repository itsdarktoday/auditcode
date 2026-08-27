import { Context } from "effect"
import type { InstanceContext } from "@/project/instance-context"
import type { WorkspaceV2 } from "@auditcode/core/workspace"

export const InstanceRef = Context.Reference<InstanceContext | undefined>("~auditcode/InstanceRef", {
  defaultValue: () => undefined,
})

export const WorkspaceRef = Context.Reference<WorkspaceV2.ID | undefined>("~auditcode/WorkspaceRef", {
  defaultValue: () => undefined,
})
