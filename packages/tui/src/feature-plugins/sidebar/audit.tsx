import type { TuiPlugin, TuiPluginApi } from "@auditcode/plugin/tui"
import type { BuiltinTuiPlugin } from "../builtins"
import { createSignal, onMount, onCleanup, Show } from "solid-js"
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import path from "node:path"
import os from "node:os"

const id = "internal:sidebar-audit"

const ENGAGEMENTS_DIR = path.join(os.homedir(), ".auditcode", "engagements")
const LAST_FILE = path.join(ENGAGEMENTS_DIR, ".last")
const SELECTED_FILE = path.join(ENGAGEMENTS_DIR, ".selected")
const PROJECTS_FILE = path.join(ENGAGEMENTS_DIR, "projects.json")

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

function resolveEngagementName(projectDir?: string): string | undefined {
  const dir = projectDir ? path.resolve(projectDir) : undefined

  // 1. Check if an engagement was explicitly chosen in dialog
  if (existsSync(SELECTED_FILE)) {
    try {
      const selected = readFileSync(SELECTED_FILE, "utf-8").trim()
      if (selected === "__none__" || selected === "__new__") return undefined
      if (selected && existsSync(path.join(ENGAGEMENTS_DIR, selected, "state.json"))) {
        return selected
      }
    } catch {}
  }

  // 2. Check if this directory is mapped in projects.json
  if (dir && existsSync(PROJECTS_FILE)) {
    try {
      const projects = JSON.parse(readFileSync(PROJECTS_FILE, "utf-8"))
      const mapped = projects[dir]
      if (mapped === "__none__" || mapped === "__new__") return undefined
      if (mapped && existsSync(path.join(ENGAGEMENTS_DIR, mapped, "state.json"))) {
        return mapped
      }
    } catch {}
  }

  // 3. Check for an engagement matching this project directory
  if (dir && existsSync(ENGAGEMENTS_DIR)) {
    const baseName = path.basename(dir).replace(/[^a-zA-Z0-9_-]/g, "-")
    if (existsSync(path.join(ENGAGEMENTS_DIR, baseName, "state.json"))) {
      return baseName
    }

    try {
      const entries = readdirSync(ENGAGEMENTS_DIR).filter((entry) => {
        if (entry.startsWith(".")) return false
        try {
          return statSync(path.join(ENGAGEMENTS_DIR, entry)).isDirectory()
        } catch {
          return false
        }
      })

      for (const entry of entries) {
        const stateFile = path.join(ENGAGEMENTS_DIR, entry, "state.json")
        if (!existsSync(stateFile)) continue
        try {
          const raw = JSON.parse(readFileSync(stateFile, "utf-8"))
          if (raw.project_dir && path.resolve(raw.project_dir) === dir) return entry
          if (raw.scope?.targets?.some((t: string) => path.resolve(t) === dir || dir.startsWith(path.resolve(t)))) {
            return entry
          }
          const contracts = Object.values(raw.contracts ?? {}) as Array<{ path?: string }>
          if (contracts.some((c) => c.path && path.resolve(c.path).startsWith(dir))) return entry
        } catch {}
      }
    } catch {}
  }

  // 4. Fallback to LAST_FILE ONLY if it matches the current project
  if (existsSync(LAST_FILE)) {
    try {
      const last = readFileSync(LAST_FILE, "utf-8").trim()
      if (!last) return undefined
      const stateFile = path.join(ENGAGEMENTS_DIR, last, "state.json")
      if (!existsSync(stateFile)) return undefined

      // If projectDir is known, verify last engagement belongs to this project
      if (dir) {
        const baseName = path.basename(dir).replace(/[^a-zA-Z0-9_-]/g, "-")
        if (last === baseName) return last
        try {
          const raw = JSON.parse(readFileSync(stateFile, "utf-8"))
          if (raw.project_dir && path.resolve(raw.project_dir) === dir) return last
          if (raw.scope?.targets?.some((t: string) => path.resolve(t) === dir || dir.startsWith(path.resolve(t)))) {
            return last
          }
          const contracts = Object.values(raw.contracts ?? {}) as Array<{ path?: string }>
          if (contracts.some((c) => c.path && path.resolve(c.path).startsWith(dir))) return last
        } catch {}
        // Does not belong to this project -- do not display stale past audit!
        return undefined
      }

      return last
    } catch {
      return undefined
    }
  }

  return undefined
}

function readCurrentAudit(projectDir?: string): AuditData | undefined {
  try {
    const name = resolveEngagementName(projectDir)
    if (!name) return undefined

    const stateFile = path.join(ENGAGEMENTS_DIR, name, "state.json")
    if (!existsSync(stateFile)) return undefined

    const content = readFileSync(stateFile, "utf-8")
    if (!content || !content.trim()) return undefined
    const raw = JSON.parse(content)

    const contracts = Object.values(raw.contracts ?? {}) as Array<{ name: string; sloc?: number }>
    const totalSloc = contracts.reduce((sum, c) => sum + (c.sloc ?? 0), 0)

    const topVulns = Object.values(raw.vulns ?? {}) as Array<{
      id?: string
      title?: string
      severity?: string
      status?: string
      contract_name?: string
      critic_review?: { verdict?: string }
    }>
    const hostVulns = Object.values(raw.hosts ?? {}).flatMap((h: any) => h.vulns ?? []) as Array<{
      id?: string
      title?: string
      severity?: string
      status?: string
      contract_name?: string
      critic_review?: { verdict?: string }
    }>

    const vulnMap = new Map<
      string,
      {
        severity?: string
        status?: string
        critic_review?: { verdict?: string }
      }
    >()

    for (const v of [...hostVulns, ...topVulns]) {
      if (!v) continue
      const key = v.id || `${v.contract_name || "global"}::${v.title || ""}`
      if (key && (!vulnMap.has(key) || v.id)) {
        vulnMap.set(key, v)
      }
    }

    let critical = 0
    let high = 0
    let medium = 0
    let low = 0
    let gas = 0
    let info = 0

    for (const v of vulnMap.values()) {
      const status = (v.status ?? "").toLowerCase()
      if (status === "false_positive" || status === "mitigated") continue
      if (v.critic_review?.verdict === "rejected") continue

      const s = (v.severity ?? "medium").toLowerCase().trim()
      if (s === "critical") critical++
      else if (s === "high") high++
      else if (s === "medium") medium++
      else if (s === "low") low++
      else if (s === "gas") gas++
      else if (s === "info") info++
      else medium++
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

function View(props: { api: TuiPluginApi; session_id?: string }) {
  const [open, setOpen] = createSignal(true)
  const currentDir = () =>
    (props.session_id ? props.api.state.session.get(props.session_id)?.directory : undefined) ||
    props.api.state.path?.directory ||
    process.cwd()

  const [data, setData] = createSignal<AuditData | undefined>(readCurrentAudit(currentDir()))
  const theme = () => props.api.theme.current

  onMount(() => {
    const timer = setInterval(() => {
      const next = readCurrentAudit(currentDir())
      setData(next)
    }, 1500)
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
      sidebar_content(_ctx, props) {
        return <View api={api} session_id={props?.session_id} />
      },
    },
  })
}

const plugin: BuiltinTuiPlugin = {
  id,
  tui,
}

export default plugin
