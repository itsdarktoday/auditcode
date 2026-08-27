export * as ScopeMatcher from "./scope-matcher"

import type { EngagementSchema } from "./schema"

// --- IPv4 ---

export function ipToInt(ip: string): number | undefined {
  const parts = ip.split(".")
  if (parts.length !== 4) return undefined
  const nums = parts.map(Number)
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return undefined
  return ((nums[0]! << 24) + (nums[1]! << 16) + (nums[2]! << 8) + nums[3]!) >>> 0
}

export function isIp(s: string): boolean {
  return ipToInt(s) !== undefined
}

export function isCidr(s: string): boolean {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(s)
  if (!m) return false
  return ipToInt(m[1]!) !== undefined && Number(m[2]) >= 0 && Number(m[2]) <= 32
}

export function isInCidr(ip: string, cidr: string): boolean {
  const [network, bits] = cidr.split("/")
  if (!bits || !network) return false
  const prefix = Number(bits)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  const ipInt = ipToInt(ip)
  const netInt = ipToInt(network)
  if (ipInt === undefined || netInt === undefined) return false
  return (ipInt & mask) === (netInt & mask)
}

// --- IPv6 ---

const IPV6_FULL_RE = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/
const IPV6_COMPRESSED_RE = /^(([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})*)?$/

export function isIpv6(s: string): boolean {
  if (s.includes(".")) return false
  if (!s.includes(":")) return false
  return IPV6_FULL_RE.test(s) || IPV6_COMPRESSED_RE.test(s)
}

export function normalizeIpv6(s: string): string | undefined {
  if (!isIpv6(s)) return undefined
  const parts = s.split("::")
  if (parts.length > 2) return undefined

  let groups: string[]
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(":") : []
    const right = parts[1] ? parts[1].split(":") : []
    const fill = 8 - left.length - right.length
    if (fill < 0) return undefined
    groups = [...left, ...Array(fill).fill("0"), ...right]
  } else {
    groups = s.split(":")
  }

  if (groups.length !== 8) return undefined
  return groups.map((g) => g.padStart(4, "0").toLowerCase()).join(":")
}

export function ipv6ToBigInt(s: string): bigint | undefined {
  const norm = normalizeIpv6(s)
  if (!norm) return undefined
  const hex = norm.replace(/:/g, "")
  return BigInt("0x" + hex)
}

export function isCidrV6(s: string): boolean {
  const m = /^(.+)\/(\d{1,3})$/.exec(s)
  if (!m) return false
  const prefix = Number(m[2])
  return isIpv6(m[1]!) && prefix >= 0 && prefix <= 128
}

export function isInCidrV6(ip: string, cidr: string): boolean {
  const m = /^(.+)\/(\d{1,3})$/.exec(cidr)
  if (!m) return false
  const prefix = Number(m[2])
  if (prefix < 0 || prefix > 128) return false
  const ipInt = ipv6ToBigInt(ip)
  const netInt = ipv6ToBigInt(m[1]!)
  if (ipInt === undefined || netInt === undefined) return false
  if (prefix === 0) return true
  const shift = BigInt(128 - prefix)
  return (ipInt >> shift) === (netInt >> shift)
}

// --- Matching ---

export function matchesWildcard(target: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1)
    return target.endsWith(suffix) && target.length > suffix.length
  }
  return false
}

export function isSubdomainOf(target: string, domain: string): boolean {
  return target.endsWith("." + domain)
}

export function extractHost(target: string): string {
  try {
    if (target.includes("://")) {
      const url = new URL(target)
      return url.hostname
    }
  } catch {
    // not a URL
  }
  const portMatch = target.match(/^([^:]+):\d+$/)
  if (portMatch && portMatch[1]) {
    return portMatch[1]
  }
  return target
}

export function matchesScopeEntry(target: string, entry: string): boolean {
  const t = target.toLowerCase()
  const e = entry.toLowerCase()
  if (t === e) return true
  if (isIp(t) && isCidr(e)) return isInCidr(t, e)
  if (isIpv6(t) && isCidrV6(e)) return isInCidrV6(t, e)
  if (e.startsWith("*.")) return matchesWildcard(t, e)
  if (!isIp(t) && !isIpv6(t) && !isIp(e) && !isCidr(e) && !isCidrV6(e)) return isSubdomainOf(t, e)
  return false
}

// --- Target extraction from commands ---

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi
const IPV6_CMD_RE = /(?:^|[\s=])([0-9a-fA-F:]{2,39}(?:\/\d{1,3})?)\b/g
const USER_AT_HOST_RE = /(?:^|[\s=])(?:[a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})?)/g
const UNC_PATH_RE = /(?:^|[\s=])(?:\\\\|\/\/)([a-zA-Z0-9._-]+)/g

const IGNORE_IPS = new Set(["127.0.0.1", "0.0.0.0", "255.255.255.255"])
const IGNORE_DOMAINS = new Set([
  "github.com", "google.com", "example.com", "localhost",
  "apt.get", "pip.install", "apt.install", "pkg.get", "brew.install",
])

// A "domain" is only treated as a real host if its final label is a plausible
// public TLD. Without this, DOMAIN_RE matches code tokens (json.load, s.recv,
// socket.socket, sys.stdin, foo.decode) as "hosts" and floods every python-in-bash
// command with false out-of-scope warnings. A curated common-TLD set kills those
// tokens (their trailing label — load/recv/socket/decode — is never a TLD) while
// keeping genuine external targets. Exotic-TLD targets simply go un-warned; that is
// acceptable for an advisory check and far better than warning on every method call.
const PUBLIC_TLDS = new Set([
  "com", "net", "org", "io", "co", "gov", "edu", "mil", "int", "biz", "info", "name", "pro",
  "app", "dev", "cloud", "tech", "xyz", "online", "site", "web", "me", "tv", "sh", "ai", "so",
  "uk", "us", "de", "fr", "ru", "cn", "jp", "in", "ca", "au", "br", "it", "es", "nl", "se", "no",
  "fi", "pl", "ch", "at", "be", "dk", "cz", "eu", "asia", "kz", "ua", "kr", "hk", "sg", "za", "tr",
])
// Reserved / internal-use TLDs. Hosts under these are internal infrastructure — in a
// pentest they almost always resolve to in-scope internal IPs, so warning on them is
// pure noise. We do NOT extract them as scope-check targets (the IP-based scope + the
// interactive gate on real external hosts cover the real cases).
const INTERNAL_TLDS = new Set([
  "local", "internal", "lan", "corp", "intranet", "home", "localdomain", "localhost",
  "test", "example", "invalid", "arpa",
])

function domainTld(domain: string): string {
  const dot = domain.lastIndexOf(".")
  return dot < 0 ? domain : domain.slice(dot + 1)
}
// A hostname is worth scope-checking only if it has a real public TLD. Internal-TLD and
// bare code-token "domains" are skipped.
function isWarnableHost(host: string): boolean {
  if (isIp(host) || isIpv6(host)) return true
  const tld = domainTld(host.toLowerCase())
  if (INTERNAL_TLDS.has(tld)) return false
  return PUBLIC_TLDS.has(tld)
}

// .zip and .mov removed — they are real TLDs
const FILE_EXTENSIONS = new Set([
  "txt", "html", "htm", "json", "xml", "csv", "yaml", "yml", "toml",
  "py", "sh", "bash", "zsh", "rb", "pl", "js", "ts", "go", "rs", "c", "cpp", "h",
  "conf", "cfg", "ini", "log", "md", "rst", "tex",
  "png", "jpg", "jpeg", "gif", "svg", "ico", "bmp", "webp",
  "tar", "gz", "bz2", "xz", "rar",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "key", "pem", "crt", "csr", "der", "p12", "pfx",
  "db", "sql", "sqlite", "bak", "tmp", "swp", "lock",
  "exe", "dll", "so", "dylib", "bin", "elf", "msi",
  "body", "out", "err", "pid", "sock", "fifo",
  "nse", "rules", "cap", "pcap", "pcapng",
  "php", "asp", "aspx", "jsp", "cgi",
])

function looksLikeFilename(s: string): boolean {
  const dot = s.lastIndexOf(".")
  if (dot <= 0) return false
  const ext = s.slice(dot + 1).toLowerCase()
  return FILE_EXTENSIONS.has(ext)
}

export function extractTargetsFromCommand(command: string): string[] {
  const targets = new Set<string>()

  for (const match of command.matchAll(IP_RE)) {
    const ip = match[0]!
    const base = ip.split("/")[0]!
    if (!IGNORE_IPS.has(base) && ipToInt(base) !== undefined) targets.add(ip)
  }

  for (const match of command.matchAll(DOMAIN_RE)) {
    const domain = match[0]!.toLowerCase()
    if (
      !IGNORE_DOMAINS.has(domain) &&
      domain.includes(".") &&
      !looksLikeFilename(domain) &&
      isWarnableHost(domain)
    ) {
      targets.add(domain)
    }
  }

  for (const match of command.matchAll(IPV6_CMD_RE)) {
    const candidate = match[1]?.trim()
    if (candidate && isIpv6(candidate.split("/")[0]!)) {
      targets.add(candidate)
    }
  }

  for (const match of command.matchAll(USER_AT_HOST_RE)) {
    const host = match[1]!
    if (!IGNORE_DOMAINS.has(host.toLowerCase()) && !looksLikeFilename(host) && isWarnableHost(host)) {
      targets.add(host)
    }
  }

  for (const match of command.matchAll(UNC_PATH_RE)) {
    const host = match[1]!
    if (!IGNORE_DOMAINS.has(host.toLowerCase()) && !looksLikeFilename(host)) {
      targets.add(host)
    }
  }

  return [...targets]
}

const KNOWN_TOOLS_RE = /\b(?:nmap|netexec|crackmapexec|ssh|scp|sftp|curl|wget|smbclient|rpcclient|evil-winrm|psexec|wmiexec|impacket|nuclei|gobuster|feroxbuster|ffuf|sqlmap|hydra|medusa|nikto|dirb|dirsearch)\b/i

export function extractTargetsWithWarning(command: string): { targets: string[]; warning?: string } {
  const targets = extractTargetsFromCommand(command)
  if (targets.length === 0 && KNOWN_TOOLS_RE.test(command)) {
    return { targets, warning: "Could not extract targets from command. Manual scope check may be needed." }
  }
  return { targets }
}

// --- Scope check ---

export type ScopeResult =
  | { inScope: true; matchedRule: string }
  | { inScope: false; matchedRule: string | null; reason: "excluded" | "not_matched" }

export function checkScope(target: string, scope: EngagementSchema.Scope): ScopeResult {
  const host = extractHost(target).toLowerCase()

  for (const exclude of scope.excludes) {
    if (matchesScopeEntry(host, exclude)) {
      return { inScope: false, matchedRule: `excluded: ${exclude}`, reason: "excluded" }
    }
  }

  for (const entry of scope.targets) {
    if (matchesScopeEntry(host, entry)) {
      return { inScope: true, matchedRule: entry }
    }
  }

  // TODO: DNS/state-based cross-matching for domain↔IP (deferred — needs pivot/SOCKS-aware resolution)
  return { inScope: false, matchedRule: null, reason: "not_matched" }
}
