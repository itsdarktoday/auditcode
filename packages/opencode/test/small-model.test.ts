import { describe, expect, test } from "bun:test"
import { Effect, Stream } from "effect"
import { LLMEvent } from "@auditcode/llm"
import { makeToolOutputSummarizer, SUMMARIZE_THRESHOLD, SUMMARIZE_TOOLS } from "../src/session/small-model"

// A fake `llm.stream` that emits the given text as one text-delta. If `text` is
// null, the stream throws when consumed (used to prove non-bash tools never stream).
function fakeStream(text: string | null) {
  return (_input: unknown) => {
    if (text === null) return Stream.fail(new Error("stream must not be called")) as any
    return Stream.fromIterable([LLMEvent.textDelta({ id: "b1", text })]) as any
  }
}

function summarizer(text: string | null) {
  return makeToolOutputSummarizer({
    stream: fakeStream(text) as any,
    model: { providerID: "test", api: { id: "small" } } as any,
    agent: {} as any,
    user: {} as any,
    sessionID: "ses_test",
  })
}

describe("makeToolOutputSummarizer", () => {
  test("only bash is in the offload allow-list", () => {
    expect(SUMMARIZE_TOOLS.has("bash")).toBe(true)
    expect(SUMMARIZE_TOOLS.has("read")).toBe(false)
    expect(SUMMARIZE_TOOLS.has("state_query")).toBe(false)
    expect(SUMMARIZE_THRESHOLD).toBeGreaterThan(0)
  })

  test("returns undefined for a non-allowed tool without ever streaming", async () => {
    const s = summarizer(null) // stream throws if called
    const out = await Effect.runPromise(s({ text: "x".repeat(9000), tool: "read" }))
    expect(out).toBeUndefined()
  })

  test("returns a digest for bash when it is smaller than the raw output", async () => {
    const s = summarizer("open ports: 22/ssh, 80/http; cred admin:admin found")
    const raw = "y".repeat(9000)
    const out = await Effect.runPromise(s({ text: raw, tool: "bash" }))
    expect(out).toEqual({ digest: "open ports: 22/ssh, 80/http; cred admin:admin found" })
  })

  test("strips <think> blocks from the digest", async () => {
    const s = summarizer("<think>let me reason</think>\n\nport 443/https open")
    const out = await Effect.runPromise(s({ text: "z".repeat(9000), tool: "bash" }))
    expect(out).toEqual({ digest: "port 443/https open" })
  })

  test("rejects a digest that is not smaller than the raw (offload bought nothing)", async () => {
    const big = "digest ".repeat(50) // ~350 chars
    const s = summarizer(big)
    const out = await Effect.runPromise(s({ text: "small raw", tool: "bash" }))
    expect(out).toBeUndefined()
  })

  test("returns undefined when the model emits nothing", async () => {
    const s = summarizer("")
    const out = await Effect.runPromise(s({ text: "w".repeat(9000), tool: "bash" }))
    expect(out).toBeUndefined()
  })

  test("surfaces an error result when the small model call fails (visibility, not silent)", async () => {
    // fakeStream(null) fails when consumed — for an eligible tool this must NOT
    // be swallowed; it must come back as { error } so the cause is visible.
    const s = summarizer(null)
    const out = await Effect.runPromise(s({ text: "v".repeat(9000), tool: "bash" }))
    expect(out && "error" in out).toBe(true)
  })
})
