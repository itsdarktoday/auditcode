import { describe, expect, test } from "bun:test"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"

// Regression: the dev.3 range-3 session flooded almost every python-in-bash command
// with "[SCOPE WARNING: possible out-of-scope targets: json.load, sys.stdin,
// socket.socket, s.recv, mail-dmz.range3.local]". The extractor matched code tokens
// and internal hostnames as hosts. These must NOT be extracted.
describe("extractTargetsFromCommand — no code-token / internal false positives", () => {
  const codeCommands = [
    `python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('x'))"`,
    `python3 - <<'EOF'\ns=socket.socket(); s.settimeout(5); s.connect((h,p)); s.recv(4096); s.sendall(b'x'); s.close()\nEOF`,
    `cat data | tr a.b c.d && foo.decode() && bar.append(x) && obj.read()`,
    `urllib.request.urlopen(req); r.status; hits.append((u,p))`,
  ]
  for (const cmd of codeCommands) {
    test(`no targets from: ${cmd.slice(0, 40)}…`, () => {
      expect(ScopeMatcher.extractTargetsFromCommand(cmd)).toEqual([])
    })
  }

  test("internal-TLD hostnames are not flagged (in-scope infra by convention)", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`curl http://mail-dmz.range3.local/`)).toEqual([])
    expect(ScopeMatcher.extractTargetsFromCommand(`smtp EHLO t.local`)).toEqual([])
    expect(ScopeMatcher.extractTargetsFromCommand(`ssh user@queue-dmz.internal`)).toEqual([])
  })
})

describe("extractTargetsFromCommand — real targets still extracted", () => {
  test("IPv4 addresses", () => {
    const t = ScopeMatcher.extractTargetsFromCommand(`curl http://172.50.1.10:3000/ ; nmap 172.50.2.20`)
    expect(t).toContain("172.50.1.10")
    expect(t).toContain("172.50.2.20")
  })
  test("CIDR", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`nmap 172.50.1.0/24`)).toContain("172.50.1.0/24")
  })
  test("genuine public-TLD domain", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`curl https://evil.com/x`)).toContain("evil.com")
    expect(ScopeMatcher.extractTargetsFromCommand(`nmap target.example.org`)).toContain("target.example.org")
  })
  test("user@host with public TLD", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`ssh admin@box.attacker.io`)).toContain("box.attacker.io")
  })
  test("invalid octets are not IPs", () => {
    expect(ScopeMatcher.extractTargetsFromCommand(`echo 999.999.1.1`)).toEqual([])
  })
})
