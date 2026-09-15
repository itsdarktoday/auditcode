import type { TuiPlugin, TuiPluginApi } from "@auditcode/plugin/tui"
import type { BuiltinTuiPlugin } from "../builtins"
import { createSignal, onMount, onCleanup, Show } from "solid-js"
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import os from "node:os"

const id = "internal:sidebar-audit"

const ENGAGEMENTS_DIR = path.join(os.homedir(), ".auditcode", "engagements")
const LAST_FILE = path.join(ENGAGEMENTS_DIR, ".last")
const SELECTED_FILE = path.join(ENGAGEMENTS_DIR, ".selected")

interface AuditData {
  name: string
  phase: string
  contractsCount: number
  totalSloc: number
  critical: number
  high: number
  medium: number
  low: number
  gas: number
  info: number
  invariantsCount: number
  pocsCount: number
}

function readCurrentAudit(): AuditData | undefined {
  try {
    let name = ""
    if (existsSync(SELECTED_FILE)) {
      const selected = readFileSync(SELECTED_FILE, "utf-8").trim()
      if (selected && selected !== "__none__" && selected !== "__new__") {
        name = selected
      }
    }
    if (!name && existsSync(LAST_FILE)) {
      name = readFileSync(LAST_FILE, "utf-8").trim()
    }
    if (!name) return undefined

    const stateFile = path.join(ENGAGEMENTS_DIR, name, "state.json")
    if (!existsSync(stateFile)) return undefined

    const raw = JSON.parse(readFileSync(stateFile, "utf-8"))
    const contracts = Object.values(raw.contracts ?? {}) as Array<{ name: string; sloc?: number }>
    const totalSloc = contracts.reduce((sum, c) => sum + (c.sloc ?? 0), 0)

    const topVulns = Object.values(raw.vulns ?? {}) as Array<{ id?: string; severity?: string }>
    const hostVulns = Object.values(raw.hosts ?? {}).flatMap((h: any) => h.vulns ?? []) as Array<{ id?: string; severity?: string }>

    const vulnMap = new Map<string, { severity?: string }>()
    for (const v of [...hostVulns, ...topVulns]) {
      vulnMap.set(v.id ?? Math.random().toString(), v)
    }

    let critical = 0
    let high = 0
    let medium = 0
    let low = 0
    let gas = 0
    let info = 0

    for (const v of vulnMap.values()) {
      const s = (v.severity ?? "medium").toLowerCase()
      if (s === "critical") critical++
      else if (s === "high") high++
      else if (s === "medium") medium++
      else if (s === "low") low++
      else if (s === "gas") gas++
      else info++
    }

    const invariants = Object.values(raw.invariants ?? {})
    const pocs = Object.values(raw.pocs ?? {})

    return {
      name: raw.name ?? name,
      phase: raw.current_phase ?? "scope_recon",
      contractsCount: contracts.length,
      totalSloc,
      critical,
      high,
      medium,
      low,
      gas,
      info,
      invariantsCount: invariants.length,
      pocsCount: pocs.length,
    }
  } catch {
    return undefined
  }
}

function View(props: { api: TuiPluginApi }) {
  const [open, setOpen] = createSignal(true)
  const [data, setData] = createSignal<AuditData | undefined>(readCurrentAudit())
  const theme = () => props.api.theme.current

  onMount(() => {
    const timer = setInterval(() => {
      setData(readCurrentAudit())
    }, 2000)
    onCleanup(() => clearInterval(timer))
  })

  return (
    <Show when={data()}>
      {(a) => (
        <box>
          <box flexDirection="row" gap={1} onMouseDown={() => setOpen((x) => !x)}>
            <text fg={theme().text}>{open() ? "▼" : "▶"}</text>
            <text fg={theme().text}>
              <b>Audit State</b>
            </text>
          </box>
          <Show when={open()}>
            <text fg={theme().textMuted}>
              {a().name} • {a().phase}
            </text>
            <text fg={theme().textMuted}>
              {a().contractsCount} contracts {a().totalSloc > 0 ? `(${a().totalSloc.toLocaleString()} SLOC)` : ""}
            </text>
            <box flexDirection="row" gap={1}>
              <text fg={theme().error}>🔴 {a().critical}</text>
              <text fg={theme().warning}>🟠 {a().high}</text>
              <text fg={theme().info}>🟡 {a().medium}</text>
              <text fg={theme().textMuted}>🔵 {a().low}</text>
            </box>
            <Show when={a().invariantsCount > 0 || a().pocsCount > 0}>
              <text fg={theme().textMuted}>
                {a().invariantsCount} invariants • {a().pocsCount} PoCs
              </text>
            </Show>
          </Show>
        </box>
      )}
    </Show>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 50,
    slots: {
      sidebar_content() {
        return <View api={api} />
      },
    },
  })
}

const plugin: BuiltinTuiPlugin = {
  id,
  tui,
}

export default plugin
