import { existsSync, readdirSync, readFileSync, writeFileSync, mkdirSync, statSync, renameSync } from "node:fs"
import path from "node:path"
import os from "node:os"
import { DialogSelect, type DialogSelectOption } from "../ui/dialog-select"
import { useDialog } from "../ui/dialog"
import { useProject } from "../context/project"

const ENGAGEMENTS_DIR = path.join(os.homedir(), ".auditcode", "engagements")
const LAST_FILE = path.join(ENGAGEMENTS_DIR, ".last")
const SELECTED_FILE = path.join(ENGAGEMENTS_DIR, ".selected")
const PROJECTS_FILE = path.join(ENGAGEMENTS_DIR, "projects.json")

interface EngagementInfo {
  name: string
  isLast: boolean
  isProjectMatch?: boolean
}

function listEngagements(directory?: string): { engagements: EngagementInfo[]; last: string | undefined } {
  if (!existsSync(ENGAGEMENTS_DIR)) return { engagements: [], last: undefined }
  const last = existsSync(LAST_FILE) ? readFileSync(LAST_FILE, "utf-8").trim() || undefined : undefined

  let projectEngagement: string | undefined
  if (directory && existsSync(PROJECTS_FILE)) {
    try {
      const projects = JSON.parse(readFileSync(PROJECTS_FILE, "utf-8"))
      projectEngagement = projects[path.resolve(directory)]
    } catch {}
  }

  const dirs = readdirSync(ENGAGEMENTS_DIR).filter((entry) => {
    if (entry.startsWith(".")) return false
    try {
      return statSync(path.join(ENGAGEMENTS_DIR, entry)).isDirectory()
    } catch {
      return false
    }
  })
  const engagements = dirs.map((name) => ({
    name,
    isLast: name === last,
    isProjectMatch: name === projectEngagement,
  }))
  engagements.sort((a, b) => {
    if (a.isProjectMatch && !b.isProjectMatch) return -1
    if (!a.isProjectMatch && b.isProjectMatch) return 1
    if (a.isLast && !b.isLast) return -1
    if (!a.isLast && b.isLast) return 1
    return a.name.localeCompare(b.name)
  })
  return { engagements, last }
}

export function writeSelectedEngagement(name: string, directory?: string) {
  mkdirSync(ENGAGEMENTS_DIR, { recursive: true, mode: 0o700 })
  const tmpSelected = `${SELECTED_FILE}.tmp.${Date.now()}`
  writeFileSync(tmpSelected, name, { encoding: "utf-8", mode: 0o600 })
  renameSync(tmpSelected, SELECTED_FILE)

  if (directory) {
    try {
      const projects = existsSync(PROJECTS_FILE) ? JSON.parse(readFileSync(PROJECTS_FILE, "utf-8")) : {}
      projects[path.resolve(directory)] = name
      const tmpProjects = `${PROJECTS_FILE}.tmp.${Date.now()}`
      writeFileSync(tmpProjects, JSON.stringify(projects, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      renameSync(tmpProjects, PROJECTS_FILE)
    } catch {}
  }
}

export function hasEngagements(): boolean {
  const { engagements } = listEngagements()
  return engagements.length > 0
}

export function DialogEngagementSelect(props?: { directory?: string }) {
  const dialog = useDialog()
  const project = useProject()
  const currentDir = props?.directory || project.instance.directory() || process.cwd()
  const { engagements } = listEngagements(currentDir)

  const options: DialogSelectOption<string>[] = [
    ...engagements.map((e) => ({
      title: e.name + (e.isProjectMatch ? " (this project)" : e.isLast ? " (last used)" : ""),
      value: e.name,
      category: "Engagements",
    })),
    {
      title: "+ New engagement",
      value: "__new__",
      category: "Actions",
    },
    {
      title: "No engagement (freestyle)",
      value: "__none__",
      category: "Actions",
    },
  ]

  return (
    <DialogSelect<string>
      title="Select Engagement"
      placeholder="Search engagements..."
      options={options}
      onSelect={(option) => {
        writeSelectedEngagement(option.value, currentDir)
        dialog.clear()
      }}
    />
  )
}
