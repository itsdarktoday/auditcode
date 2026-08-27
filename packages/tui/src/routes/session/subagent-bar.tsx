import { createMemo, createSignal, For, Show } from "solid-js"
import { useRouteData } from "../../context/route"
import { useRoute } from "../../context/route"
import { useSync } from "../../context/sync"
import { useTheme } from "../../context/theme"
import { Spinner } from "../../component/spinner"
import { SplitBorder } from "../../ui/border"
import { Locale } from "../../util/locale"
import { useTerminalDimensions } from "@opentui/solid"
import type { ToolPart } from "@auditcode/sdk/v2"

type Status = "running" | "done" | "error"

type Entry = {
  sessionID: string
  label: string
  description: string
  status: Status
  detail?: string
}

const MAX_ROWS = 6

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined
}

// Live list of the root session's subagents, always visible at the bottom.
// Click a row to open that subagent's session and watch its actions in real
// time. Derived entirely from data the TUI already syncs (task tool parts +
// child session busy/idle status) — no new server/event plumbing.
export function SubagentBar() {
  const route = useRouteData("session")
  const sync = useSync()
  const { navigate } = useRoute()
  const { theme } = useTheme()
  const [hover, setHover] = createSignal<string | null>(null)
  useTerminalDimensions()

  const childActivity = (childID: string): string | undefined => {
    const status = sync.data.session_status[childID]
    if (status?.type === "retry") return `retrying (attempt ${status.attempt})`
    const msgs = sync.data.message[childID] ?? []
    const tools = msgs.flatMap((m) =>
      (sync.data.part[m.id] ?? []).filter((p): p is ToolPart => p.type === "tool"),
    )
    const current = tools.findLast(
      (t) => (t.state.status === "running" || t.state.status === "completed") && stringValue((t.state as any).title),
    )
    if (current) {
      const title = stringValue((current.state as any).title)
      return `${Locale.titlecase(current.tool)}${title ? ` ${Locale.truncate(title, 40)}` : ""}`
    }
    if (tools.length > 0) return `${tools.length} tool call${tools.length === 1 ? "" : "s"}`
    return undefined
  }

  const subagents = createMemo<Entry[]>(() => {
    // Derive from CHILD SESSIONS, not from `task` tool parts. Both spawn paths —
    // the manual `task` tool and the deterministic orchestrator (which dispatches
    // from inside a single `task_graph` call, so there is no per-subagent `task`
    // part) — create a child session titled "<desc> (@<agent> subagent)". Keying
    // off child sessions makes the bar work for either, and matches how the nav
    // and session tree already enumerate children (routes/session/index.tsx).
    const rootID = route.sessionID
    const entries: Entry[] = []
    for (const child of sync.data.session) {
      if (child.parentID !== rootID) continue
      const agentMatch = child.title?.match(/@(\w+) subagent/)
      if (!agentMatch) continue // only real subagent sessions, not hidden utility ones
      // Child-session liveness is the source of truth for "running": a present
      // session_status entry means busy (idle deletes it — see session/status.ts).
      const childStatus = sync.data.session_status[child.id]
      const childActive = childStatus !== undefined && childStatus.type !== "idle"
      if (!childActive) continue // bar tracks in-flight work only; finished ones drop
      entries.push({
        sessionID: child.id,
        label: Locale.titlecase(agentMatch[1]),
        description: (child.title ?? "").replace(/\s*\(@\w+ subagent\)\s*$/, "").trim(),
        status: "running",
        detail: childActivity(child.id),
      })
    }
    return entries
  })

  const shown = createMemo(() => subagents().slice(0, MAX_ROWS))
  const overflow = createMemo(() => subagents().length - shown().length)

  const icon = (status: Status) => (status === "done" ? "✓" : status === "error" ? "✗" : "·")
  const iconColor = (status: Status) =>
    status === "done" ? theme.success : status === "error" ? theme.error : theme.textMuted

  return (
    <Show when={subagents().length > 0}>
      <box flexShrink={0}>
        <box
          paddingTop={1}
          paddingBottom={1}
          paddingLeft={2}
          paddingRight={1}
          {...SplitBorder}
          border={["left"]}
          borderColor={theme.border}
          flexShrink={0}
          backgroundColor={theme.backgroundPanel}
          flexDirection="column"
        >
          <text fg={theme.textMuted}>
            Subagents ({subagents().length} running) — click to view
          </text>
          <For each={shown()}>
            {(entry) => (
              <box
                flexDirection="row"
                gap={1}
                onMouseOver={() => setHover(entry.sessionID)}
                onMouseOut={() => setHover(null)}
                onMouseUp={() => navigate({ type: "session", sessionID: entry.sessionID })}
                backgroundColor={hover() === entry.sessionID ? theme.backgroundElement : theme.backgroundPanel}
              >
                <Show when={entry.status === "running"} fallback={<text fg={iconColor(entry.status)}>{icon(entry.status)}</text>}>
                  <Spinner />
                </Show>
                <text fg={theme.text} wrapMode="none">
                  <b>{entry.label}</b>
                </text>
                <text fg={theme.textMuted} wrapMode="none">
                  {[Locale.truncate(entry.description, 48), entry.detail && `↳ ${entry.detail}`]
                    .filter(Boolean)
                    .join("  ")}
                </text>
              </box>
            )}
          </For>
          <Show when={overflow() > 0}>
            <text fg={theme.textMuted}>… and {overflow()} more</text>
          </Show>
        </box>
      </box>
    </Show>
  )
}
