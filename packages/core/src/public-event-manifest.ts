export * as PublicEventManifest from "./public-event-manifest"

import { Event } from "@auditcode/schema/event"
import { EventManifest } from "@auditcode/schema/event-manifest"

export const Definitions = EventManifest.ServerDefinitions
export const Latest = Event.latest(Definitions)
