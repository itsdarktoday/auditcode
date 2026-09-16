import { createMemo, createSignal } from "solid-js"
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
  const current = createMemo(() => {
    const configured = sync.data.config.agent?.[props.team]?.model
    return configured ?? NONE
  })

  function apply(value: string) {
    const model = value === NONE ? "" : value
    void sdk.client.global.config
      .update({ config: { agent: { [props.team]: { model } } } })
      .then(() =>
        toast.show({
          variant: "success",
          message:
            value === NONE
              ? `${label()} model set to default (session model)`
              : `${label()} model set: ${value}`,
          duration: 3000,
        }),
      )
      .catch((e: unknown) =>
        toast.show({ variant: "error", message: `Failed to set ${label()} model: ${String(e)}`, duration: 4000 }),
      )
    dialog.clear()
  }

  const options = createMemo(() => {
    const needle = query().trim()
    const none = {
      value: NONE,
      title: "Default — inherit active session model",
      description: `Runs ${label()} on the same model selected in current session`,
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
          map(([model, info]) => ({
            value: `${provider.id}/${model}`,
            title: info.name ?? model,
            releaseDate: info.release_date,
            category: provider.name,
            footer: info.cost?.input === 0 ? "Free" : undefined,
            onSelect: () => apply(`${provider.id}/${model}`),
          })),
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
      title={`Select model for ${label()}`}
      current={current()}
    />
  )
}
