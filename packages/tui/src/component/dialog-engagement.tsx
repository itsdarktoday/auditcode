import { existsSync, readdirSync, readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs"
import path from "node:path"
import os from "node:os"
import { DialogSelect, type DialogSelectOption } from "../ui/dialog-select"
import { useDialog } from "../ui/dialog"

const ENGAGEMENTS_DIR = path.join(os.homedir(), ".auditcode", "engagements")
const LAST_FILE = path.join(ENGAGEMENTS_DIR, ".last")
const SELECTED_FILE = path.join(ENGAGEMENTS_DIR, ".selected")

interface EngagementInfo {
  name: string
  isLast: boolean
}

function listEngagements(): { engagements: EngagementInfo[]; last: string | undefined } {
  if (!existsSync(ENGAGEMENTS_DIR)) return { engagements: [], last: undefined }
  const last = existsSync(LAST_FILE) ? readFileSync(LAST_FILE, "utf-8").trim() || undefined : undefined
  const dirs = readdirSync(ENGAGEMENTS_DIR).filter((entry) => {
    if (entry.startsWith(".")) return false
    try {
      return statSync(path.join(ENGAGEMENTS_DIR, entry)).isDirectory()
    } catch {
      return false
    }
  })
  const engagements = dirs.map((name) => ({ name, isLast: name === last }))
  engagements.sort((a, b) => {
    if (a.isLast && !b.isLast) return -1
    if (!a.isLast && b.isLast) return 1
    return a.name.localeCompare(b.name)
  })
  return { engagements, last }
}

export function writeSelectedEngagement(name: string) {
  mkdirSync(ENGAGEMENTS_DIR, { recursive: true, mode: 0o700 })
  writeFileSync(SELECTED_FILE, name, { encoding: "utf-8", mode: 0o600 })
}

export function hasEngagements(): boolean {
  const { engagements } = listEngagements()
  return engagements.length > 0
}

export function DialogEngagementSelect() {
  const dialog = useDialog()
  const { engagements } = listEngagements()

  const options: DialogSelectOption<string>[] = [
    ...engagements.map((e) => ({
      title: e.name + (e.isLast ? " (last used)" : ""),
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
        writeSelectedEngagement(option.value)
        dialog.clear()
      }}
    />
  )
}
