import { createMemo, createSignal } from "solid-js"
import { reconcile } from "solid-js/store"
import { pipe, flatMap, entries, filter, map, sortBy } from "remeda"
import * as fuzzysort from "fuzzysort"
import { DialogSelect } from "../ui/dialog-select"
import { useDialog } from "../ui/dialog"
import { useSync } from "../context/sync"
import { useSDK } from "../context/sdk"
import { useToast } from "../ui/toast"
import { sortModelOptions } from "./dialog-model"

const NONE = " none"

export function DialogTeamModel(props: { team: "red_team" | "blue_team" }) {
  const sync = useSync()
  const sdk = useSDK()
  const toast = useToast()
  const dialog = useDialog()
  const [query, setQuery] = createSignal("")

  const label = createMemo(() => (props.team === "red_team" ? "Red Team (Attacker)" : "Blue Team (Defender)"))

  const configured = createMemo(() => sync.data.config.agent?.[props.team]?.model)
  const current = createMemo(() => {
    const val = configured()
    if (!val) return NONE
    return val
  })

  const currentDisplay = createMemo(() => {
    const val = configured()
    if (!val || val === NONE) return "Default (Session Model)"
    return val
  })

  function apply(value: string) {
    const model = value === NONE ? "" : value

    // 1. Immediately update local Solid store in sync so it reflects instantly across the UI
    const currentAgent = sync.data.config.agent ?? {}
    sync.set("config", "agent", {
      ...currentAgent,
      [props.team]: {
        ...(currentAgent[props.team] ?? {}),
        model,
      },
    })

    // 2. Persist to global config on server
    void sdk.client.global.config
      .update({ config: { agent: { [props.team]: { model } } } })
      .then((res) => {
        if (res.data) {
          sync.set("config", reconcile(res.data))
        }
        toast.show({
          variant: "success",
          message:
            value === NONE
              ? `${label()} set to Default (session model)`
              : `${label()} model set: ${value}`,
          duration: 3000,
        })
      })
      .catch((e: unknown) =>
        toast.show({ variant: "error", message: `Failed to set ${label()} model: ${String(e)}`, duration: 4000 }),
      )
    dialog.clear()
  }

  const options = createMemo(() => {
    const needle = query().trim()
    const isNone = current() === NONE
    const none = {
      value: NONE,
      title: "Default — inherit active session model",
      description: `Runs ${label()} on the same model selected in current session`,
      footer: isNone ? "✓ Selected" : undefined,
      releaseDate: "9999",
      onSelect: () => apply(NONE),
    }
    const providerOptions = pipe(
      sync.data.provider,
      sortBy((provider) => provider.name),
      flatMap((provider) =>
        pipe(
          provider.models,
          entries(),
          filter(([_, info]) => info.status !== "deprecated"),
          map(([model, info]) => {
            const val = `${provider.id}/${model}`
            const isSelected = val === current()
            return {
              value: val,
              title: info.name ?? model,
              releaseDate: info.release_date,
              category: provider.name,
              footer: isSelected ? "✓ Selected" : info.cost?.input === 0 ? "Free" : undefined,
              onSelect: () => apply(val),
            }
          }),
          (opts) => sortModelOptions(opts, false),
        ),
      ),
    )
    if (needle) return fuzzysort.go(needle, providerOptions, { keys: ["title", "category"] }).map((x) => x.obj)
    return [none, ...providerOptions]
  })

  return (
    <DialogSelect<string>
      options={options()}
      onFilter={setQuery}
      flat={true}
      skipFilter={true}
      title={`Select model for ${label()} (Current: ${currentDisplay()})`}
      current={current()}
    />
  )
}
