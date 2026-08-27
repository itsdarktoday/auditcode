import { describe, expect, test } from "bun:test"
import { parseResultTrailer } from "../src/tool/task"

describe("parseResultTrailer (I-1)", () => {
  test("returns undefined when no trailer is present (legacy heuristic fallback)", () => {
    expect(parseResultTrailer("I found a KeePass DB at /ftp/ but could not crack it.")).toBeUndefined()
  })

  test("parses findings/dead_ends/next from the trailer", () => {
    const text = `Some prose about the run.
<agent-result>
findings: SQLi on /login (confirmed) | admin:admin default creds
dead_ends: open-redirect on /r (validated) | JWT alg:none (rejected)
next: try SSTI on /profile | spray creds on SSH
</agent-result>`
    const r = parseResultTrailer(text)!
    expect(r.findings).toEqual(["SQLi on /login (confirmed)", "admin:admin default creds"])
    expect(r.failures).toEqual(["open-redirect on /r (validated)", "JWT alg:none (rejected)"])
    expect(r.next).toEqual(["try SSTI on /profile", "spray creds on SSH"])
  })

  test("a real finding is NOT misfiled as a failure (the bug I-1 fixes)", () => {
    // Prose that the substring heuristic would file under "failures" (contains
    // "could not"/"failed"), but the trailer classifies correctly as a finding.
    const text = `I could not crack the hash, but the /ftp/ dir listing exposes incident-support.kdbx.
<agent-result>
findings: /ftp/ exposes incident-support.kdbx (KeePass DB)
dead_ends: none
next: exfiltrate and crack the kdbx offline
</agent-result>`
    const r = parseResultTrailer(text)!
    expect(r.findings).toEqual(["/ftp/ exposes incident-support.kdbx (KeePass DB)"])
    expect(r.failures).toEqual([]) // 'none' -> empty, not a fabricated failure
    expect(r.next).toEqual(["exfiltrate and crack the kdbx offline"])
  })

  test("'none' yields empty sections", () => {
    const r = parseResultTrailer("<agent-result>\nfindings: none\ndead_ends: none\nnext: none\n</agent-result>")!
    expect(r.findings).toEqual([])
    expect(r.failures).toEqual([])
    expect(r.next).toEqual([])
  })

  test("tolerates label synonyms (failures/recommended)", () => {
    const r = parseResultTrailer(
      "<agent-result>\nfindings: x\nfailures: y\nrecommended: z\n</agent-result>",
    )!
    expect(r.findings).toEqual(["x"])
    expect(r.failures).toEqual(["y"])
    expect(r.next).toEqual(["z"])
  })

  test("uses the LAST trailer if the model emitted more than one", () => {
    const r = parseResultTrailer(
      "<agent-result>\nfindings: draft\n</agent-result>\nmore work\n<agent-result>\nfindings: final\n</agent-result>",
    )!
    expect(r.findings).toEqual(["final"])
  })
})
