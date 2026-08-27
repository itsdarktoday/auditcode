import { Effect, Stream } from "effect"
import { LLMEvent } from "@auditcode/llm"
import type { Agent } from "../agent/agent"
import type { Provider } from "@/provider/provider"
import type { SessionV1 } from "@auditcode/core/v1/session"
import type { LLM } from "./llm"
import { isRecord } from "@/util/record"

// AR2 (cheap-model offload) — NARROW scope: digest large raw tool outputs on the
// small model before they enter the expensive model's transcript. The raw output
// is kept retrievable by ref, so the strategist can always pull ground truth.
//
// Opt-in only: the summarizer is built solely when a small model resolves
// (config `small_model`, or the provider's own small-model family). If none
// resolves, no summarizer is passed and every tool output stays verbatim — we
// never silently switch provider or drop detail.

// Outputs at or above this many characters are candidates for offload. Below it,
// the replay cost is small enough that keeping the raw output verbatim is cheaper
// than a round-trip to the small model. Set at 10KB (not lower) to protect DEPTH:
// mid-size raw outputs stay verbatim so a subtle-but-crucial detail on a hard
// challenge isn't compressed away — only genuinely large dumps get digested.
export const SUMMARIZE_THRESHOLD = 10000

// Cap the text actually SENT to the small model. Large scan dumps make the
// offload call slow enough to time out (and it competes for provider
// concurrency). The full raw output is still kept retrievable by ref, so
// digesting a head+tail sample is safe — the digest is lossy either way and the
// ref holds ground truth.
export const MAX_DIGEST_INPUT = 16000

// Only these tools' raw output is offloaded. Deliberately narrow: `bash` is where
// the 10-50 KB scan/enumeration dumps come from. Structured/precision tools
// (parsers, state_query, read, report_gen, …) are never summarized — their output
// is already compact and the agent needs it verbatim.
export const SUMMARIZE_TOOLS = new Set(["bash"])

// Universal backstop cap (C-4). AR2 offload only covers `bash` and only when a
// small model is configured; every other large output (a parser dumping a big
// /24 scan, state_query, or bash with no small model) previously rode the
// expensive transcript verbatim. Any tool output above this that the tool did
// NOT already summarize/truncate/ref is capped at the result boundary, with the
// full text kept retrievable by ref. Set above SUMMARIZE_THRESHOLD so the
// cheap-model digest (better than a blunt cut) always takes precedence for bash.
export const OUTPUT_HARD_CAP = 16000

// C-4 (pure, tested): decide whether a tool result still needs the backstop cap.
// Only STRING outputs strictly above the cap that the tool did NOT already handle
// (summarized / truncated / written to a ref) are capped — so we never double-cap
// or clip an output a precision path already shaped.
export function shouldCapOutput(output: unknown, metadata: unknown, cap = OUTPUT_HARD_CAP): output is string {
  if (typeof output !== "string" || output.length <= cap) return false
  if (isRecord(metadata) && metadata.summarized === true) return false
  if (isRecord(metadata) && metadata.truncated === true) return false
  if (isRecord(metadata) && typeof metadata.outputPath === "string") return false
  return true
}

// C-4 (pure, tested): build the capped transcript copy. INVARIANT: the first `cap`
// characters are preserved VERBATIM (no head loss), the total byte count is stated,
// and — when a ref was written — the full text stays retrievable. Returns the new
// output plus a metadata patch to merge onto the part.
export function buildCappedOutput(
  raw: string,
  ref: string | undefined,
  cap = OUTPUT_HARD_CAP,
): { output: string; metadataPatch: { truncated: true; original_bytes: number; outputPath?: string } } {
  return {
    output: `${raw.slice(0, cap)}\n\n[Output truncated: ${raw.length} bytes total, showing the first ${cap}.${
      ref ? ` Full output saved to ${ref} — read it for exact detail.` : ""
    } Parser tools also write full results to engagement state — use state_query.]`,
    metadataPatch: { truncated: true, original_bytes: raw.length, ...(ref ? { outputPath: ref } : {}) },
  }
}

const SYSTEM = `You are a compression worker for a penetration-testing agent. You receive the raw stdout/stderr of a shell command (nmap, nuclei, gobuster, netexec, curl, cat, etc.). Produce a DENSE, factual digest that keeps everything the strategist needs and drops the rest.

KEEP (verbatim, never mask or omit):
- credentials, tokens, hashes, API keys, secrets, session cookies
- open ports/services + versions, hostnames, URLs, endpoints, IPs, usernames
- vulnerabilities, CVEs, error/stack-trace lines that indicate a finding
- file paths, config values, flags, interesting response bodies

DROP: banners, ASCII art, progress bars, spinners, decorative separators, repeated boilerplate, timing/percentage noise, help text.

RULES:
- Preserve exact strings for anything exploitable (creds/tokens/paths/versions/payloads). Do NOT paraphrase those.
- Do NOT invent, infer, or add commentary, recommendations, or next steps.
- If the output is an error, a timeout, or empty, say so in one line.
- Output plain text. No markdown headers, no preamble like "Here is the digest".`

export interface SummarizeInput {
  text: string
  tool: string
}

// Explicit outcome so failures are VISIBLE instead of a silent no-op:
//  - undefined      → tool not eligible / digest not worthwhile → keep raw, no note
//  - { digest }     → success, use the compact digest
//  - { error }      → offload was attempted but the small model call failed →
//                     keep raw AND surface the reason so the cause is catchable
export type SummarizeResult = { digest: string } | { error: string } | undefined
export type Summarizer = (input: SummarizeInput) => Effect.Effect<SummarizeResult>

/**
 * Build a tool-output summarizer bound to a resolved small model. Returns a
 * function that yields a compact digest, or `undefined` when summarization
 * failed / was empty / not worthwhile — in which case the caller keeps the raw
 * output unchanged.
 */
export function makeToolOutputSummarizer(deps: {
  stream: LLM.Interface["stream"]
  model: Provider.Model
  agent: Agent.Info
  user: SessionV1.User
  sessionID: string
}): Summarizer {
  return (input: SummarizeInput) =>
    Effect.gen(function* () {
      if (!SUMMARIZE_TOOLS.has(input.tool)) return undefined
      const raw = input.text
      // Head+tail sample so the small model isn't fed (and slowed by) the whole
      // dump. Scan output is front-loaded; the tail often holds the summary line.
      const sample =
        raw.length > MAX_DIGEST_INPUT
          ? raw.slice(0, MAX_DIGEST_INPUT - 4000) +
            "\n\n...[middle truncated for digest — full output kept in the ref]...\n\n" +
            raw.slice(-4000)
          : raw
      let errReason: string | undefined
      const digest = yield* deps
        .stream({
          agent: deps.agent,
          user: deps.user,
          system: [SYSTEM],
          small: true,
          tools: {},
          model: deps.model,
          sessionID: deps.sessionID,
          retries: 1,
          messages: [
            {
              role: "user",
              content: `Tool: ${input.tool}\nRaw output (${raw.length} bytes total${
                raw.length > MAX_DIGEST_INPUT ? `, showing a head+tail sample` : ""
              }) — digest it:\n\n${sample}`,
            },
          ],
        })
        .pipe(
          Stream.filter(LLMEvent.is.textDelta),
          Stream.map((e) => e.text),
          Stream.mkString,
          Effect.timeout("90 seconds"),
          // Capture + log the REAL failure instead of swallowing it, so a
          // misconfigured / unavailable small model is diagnosable.
          Effect.tapError((err) => {
            errReason = String(err).slice(0, 240)
            return Effect.logWarning(
              `[AR2] small_model offload call failed for tool '${input.tool}' (model ${deps.model.providerID}/${deps.model.api.id}): ${errReason}`,
            )
          }),
          Effect.catch(() => Effect.succeed("")),
        )
      if (errReason) return { error: errReason }
      const cleaned = digest.replace(/<think>[\s\S]*?<\/think>\s*/g, "").trim()
      // Only accept a digest that is actually smaller than the raw; otherwise the
      // offload bought nothing and the raw is more faithful.
      if (!cleaned || cleaned.length >= raw.length) return undefined
      return { digest: cleaned }
    })
}
