import path from "path"
import { createHash } from "crypto"
import { Effect } from "effect"
import { FSUtil } from "@auditcode/core/fs-util"
import { Global } from "@auditcode/core/global"

export * as BundledSkills from "./bundled"

// The default ("bundled") skill set is embedded into the binary at build time
// (see script/build.ts, which emits the `auditcode-skills.gen.ts` virtual
// module). In dev the binary is not compiled and the module does not exist;
// loadBundle then returns null and seeding is skipped — dev discovers skills
// from the repo ./skills via the `skills.paths` config instead.
export type EmbeddedBundle = {
  // Build version this bundle shipped with; used as the re-seed trigger.
  version: string
  // Relative skill path (e.g. "services/smb/SKILL.md") -> path readable by
  // FSUtil.readFile (an embedded bunfs path in a real binary).
  files: Record<string, string>
}

async function loadBundle(): Promise<EmbeddedBundle | null> {
  try {
    // @ts-expect-error - generated at build time by script/build.ts
    const mod = await import("auditcode-skills.gen.ts")
    const files = mod.default as Record<string, string> | undefined
    if (!files || typeof files !== "object") return null
    return { version: (mod.version as string | undefined) ?? "0.0.0", files }
  } catch {
    return null
  }
}

function sha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex")
}

// Seed ~/.auditcode/skills/bundled from the binary-embedded skill set. Runs on
// first launch and whenever the embedded bundle version differs from what is on
// disk. No-op in dev (nothing embedded). Best-effort — see apply.
export const seed = Effect.fn("Skill.seedBundled")(function* (fsys: FSUtil.Interface, global: Global.Interface) {
  const bundle = yield* Effect.promise(loadBundle)
  if (!bundle) return
  yield* apply(fsys, global, bundle)
})

// Replace bundled/ wholesale from `bundle` via an atomic staged swap (mirrors
// the swap in ./discovery.ts) when the on-disk manifest version differs. user/
// and packs/ are physically separate and never touched. Best-effort: any
// failure is logged and startup proceeds with whatever is on disk.
export const apply = Effect.fn("Skill.applyBundled")(function* (
  fsys: FSUtil.Interface,
  global: Global.Interface,
  bundle: EmbeddedBundle,
) {
  const target = path.join(global.home, ".auditcode", "skills", "bundled")
  const manifestPath = path.join(target, ".manifest.json")

  const currentRaw = yield* fsys.readFileStringSafe(manifestPath).pipe(Effect.catch(() => Effect.succeed(undefined)))
  if (currentRaw) {
    let installed: string | undefined
    try {
      installed = (JSON.parse(currentRaw) as { bundleVersion?: string }).bundleVersion
    } catch {
      installed = undefined
    }
    if (installed === bundle.version) return
  }

  const token = crypto.randomUUID()
  const staging = `${target}.tmp-${token}`
  const backup = `${target}.old-${token}`

  yield* Effect.gen(function* () {
    const checksums: Record<string, string> = {}
    for (const [rel, embedded] of Object.entries(bundle.files)) {
      const body = yield* fsys.readFile(embedded)
      checksums[rel] = sha256(body)
      yield* fsys.writeWithDirs(path.join(staging, rel), body)
    }
    // Manifest records per-file checksums so migration (P5) can tell a pristine
    // bundled skill from a user-modified one when relocating the legacy layout.
    yield* fsys.writeWithDirs(
      path.join(staging, ".manifest.json"),
      JSON.stringify({ bundleVersion: bundle.version, files: checksums }, null, 2),
    )

    yield* Effect.uninterruptible(
      Effect.gen(function* () {
        const exists = yield* fsys.existsSafe(target)
        if (exists) yield* fsys.rename(target, backup)
        yield* fsys.rename(staging, target).pipe(
          Effect.catch((error) =>
            Effect.gen(function* () {
              if (exists) yield* fsys.rename(backup, target).pipe(Effect.ignore)
              return yield* Effect.fail(error)
            }),
          ),
        )
        if (exists) yield* fsys.remove(backup, { recursive: true, force: true }).pipe(Effect.ignore)
      }),
    )

    yield* Effect.logInfo("seeded bundled skills", {
      version: bundle.version,
      count: Object.keys(bundle.files).length,
    })
  }).pipe(
    Effect.catch((error) => Effect.logError("failed to seed bundled skills", { error })),
    Effect.ensuring(fsys.remove(staging, { recursive: true, force: true }).pipe(Effect.ignore)),
  )
})
