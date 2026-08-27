import { describe, expect, test } from "bun:test"
import {
  isIp,
  isCidr,
  isInCidr,
  isIpv6,
  normalizeIpv6,
  isInCidrV6,
  isCidrV6,
  matchesWildcard,
  matchesScopeEntry,
  checkScope,
  extractTargetsFromCommand,
  extractHost,
  ipToInt,
} from "@auditcode/core/engagement/scope-matcher"

describe("ipToInt", () => {
  test("valid IPs", () => {
    expect(ipToInt("10.0.0.1")).toBe(167772161)
    expect(ipToInt("0.0.0.0")).toBe(0)
    expect(ipToInt("255.255.255.255")).toBe(4294967295)
  })

  test("rejects invalid IPs", () => {
    expect(ipToInt("999.1.1.1")).toBeUndefined()
    expect(ipToInt("256.0.0.1")).toBeUndefined()
    expect(ipToInt("10.0.0")).toBeUndefined()
    expect(ipToInt("10.0.0.1.2")).toBeUndefined()
    expect(ipToInt("abc")).toBeUndefined()
  })
})

describe("isIp", () => {
  test("valid IPs return true", () => {
    expect(isIp("10.0.0.1")).toBe(true)
    expect(isIp("192.168.1.1")).toBe(true)
  })

  test("rejects octets > 255", () => {
    expect(isIp("999.1.1.1")).toBe(false)
    expect(isIp("10.256.0.1")).toBe(false)
  })

  test("rejects non-IPs", () => {
    expect(isIp("example.com")).toBe(false)
    expect(isIp("")).toBe(false)
  })
})

describe("isCidr", () => {
  test("valid CIDRs", () => {
    expect(isCidr("10.0.0.0/8")).toBe(true)
    expect(isCidr("192.168.1.0/24")).toBe(true)
    expect(isCidr("0.0.0.0/0")).toBe(true)
  })

  test("rejects invalid CIDRs", () => {
    expect(isCidr("999.0.0.0/8")).toBe(false)
    expect(isCidr("10.0.0.0/33")).toBe(false)
    expect(isCidr("10.0.0.0")).toBe(false)
  })
})

describe("isInCidr", () => {
  test("basic containment", () => {
    expect(isInCidr("10.0.0.1", "10.0.0.0/8")).toBe(true)
    expect(isInCidr("10.255.0.1", "10.0.0.0/8")).toBe(true)
    expect(isInCidr("11.0.0.1", "10.0.0.0/8")).toBe(false)
  })

  test("/32 matches exact IP", () => {
    expect(isInCidr("10.0.0.1", "10.0.0.1/32")).toBe(true)
    expect(isInCidr("10.0.0.2", "10.0.0.1/32")).toBe(false)
  })

  test("/0 matches everything", () => {
    expect(isInCidr("1.2.3.4", "0.0.0.0/0")).toBe(true)
  })
})

describe("IPv6", () => {
  test("isIpv6 detects valid addresses", () => {
    expect(isIpv6("::1")).toBe(true)
    expect(isIpv6("fe80::1")).toBe(true)
    expect(isIpv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe(true)
    expect(isIpv6("::")).toBe(true)
  })

  test("isIpv6 rejects non-IPv6", () => {
    expect(isIpv6("10.0.0.1")).toBe(false)
    expect(isIpv6("example.com")).toBe(false)
    expect(isIpv6("")).toBe(false)
  })

  test("normalizeIpv6 expands compressed", () => {
    expect(normalizeIpv6("::1")).toBe("0000:0000:0000:0000:0000:0000:0000:0001")
    expect(normalizeIpv6("fe80::1")).toBe("fe80:0000:0000:0000:0000:0000:0000:0001")
  })

  test("isCidrV6", () => {
    expect(isCidrV6("fe80::/10")).toBe(true)
    expect(isCidrV6("::1/128")).toBe(true)
    expect(isCidrV6("10.0.0.0/8")).toBe(false)
  })

  test("isInCidrV6", () => {
    expect(isInCidrV6("fe80::1", "fe80::/10")).toBe(true)
    expect(isInCidrV6("2001:db8::1", "fe80::/10")).toBe(false)
  })
})

describe("matchesWildcard", () => {
  test("matches subdomain", () => {
    expect(matchesWildcard("sub.example.com", "*.example.com")).toBe(true)
    expect(matchesWildcard("deep.sub.example.com", "*.example.com")).toBe(true)
  })

  test("does NOT match apex domain", () => {
    expect(matchesWildcard("example.com", "*.example.com")).toBe(false)
  })

  test("no match for different domain", () => {
    expect(matchesWildcard("other.com", "*.example.com")).toBe(false)
  })
})

describe("matchesScopeEntry", () => {
  test("exact match", () => {
    expect(matchesScopeEntry("example.com", "example.com")).toBe(true)
  })

  test("case insensitive", () => {
    expect(matchesScopeEntry("Example.COM", "example.com")).toBe(true)
    expect(matchesScopeEntry("example.com", "Example.COM")).toBe(true)
  })

  test("IP in CIDR", () => {
    expect(matchesScopeEntry("10.0.0.5", "10.0.0.0/24")).toBe(true)
    expect(matchesScopeEntry("10.0.1.5", "10.0.0.0/24")).toBe(false)
  })

  test("subdomain of domain", () => {
    expect(matchesScopeEntry("sub.example.com", "example.com")).toBe(true)
    expect(matchesScopeEntry("example.com", "other.com")).toBe(false)
  })

  test("wildcard matching", () => {
    expect(matchesScopeEntry("sub.example.com", "*.example.com")).toBe(true)
    expect(matchesScopeEntry("example.com", "*.example.com")).toBe(false)
  })
})

describe("checkScope", () => {
  test("in scope when matching target", () => {
    const result = checkScope("10.0.0.5", {
      targets: ["10.0.0.0/24"],
      excludes: [],
    })
    expect(result.inScope).toBe(true)
  })

  test("excluded takes priority", () => {
    const result = checkScope("10.0.0.5", {
      targets: ["10.0.0.0/24"],
      excludes: ["10.0.0.5"],
    })
    expect(result.inScope).toBe(false)
    if (!result.inScope) expect(result.reason).toBe("excluded")
  })

  test("not in scope when no match", () => {
    const result = checkScope("192.168.1.1", {
      targets: ["10.0.0.0/24"],
      excludes: [],
    })
    expect(result.inScope).toBe(false)
    if (!result.inScope) expect(result.reason).toBe("not_matched")
  })

  test("case insensitive domain match", () => {
    const result = checkScope("Example.COM", {
      targets: ["example.com"],
      excludes: [],
    })
    expect(result.inScope).toBe(true)
  })

  test("wildcard domain in targets", () => {
    const result = checkScope("sub.example.com", {
      targets: ["*.example.com"],
      excludes: [],
    })
    expect(result.inScope).toBe(true)
  })

  test("extract host from URL", () => {
    const result = checkScope("http://10.0.0.5:8080/api", {
      targets: ["10.0.0.0/24"],
      excludes: [],
    })
    expect(result.inScope).toBe(true)
  })
})

describe("extractHost", () => {
  test("plain host", () => {
    expect(extractHost("10.0.0.1")).toBe("10.0.0.1")
  })

  test("URL", () => {
    expect(extractHost("http://example.com/path")).toBe("example.com")
  })

  test("host:port", () => {
    expect(extractHost("10.0.0.1:8080")).toBe("10.0.0.1")
  })
})

describe("extractTargetsFromCommand", () => {
  test("extracts IPs", () => {
    const targets = extractTargetsFromCommand("nmap -sV 10.0.0.1 10.0.0.2")
    expect(targets).toContain("10.0.0.1")
    expect(targets).toContain("10.0.0.2")
  })

  test("extracts CIDR", () => {
    const targets = extractTargetsFromCommand("nmap 10.0.0.0/24")
    expect(targets).toContain("10.0.0.0/24")
  })

  test("extracts domains", () => {
    const targets = extractTargetsFromCommand("nmap target.example.com")
    expect(targets).toContain("target.example.com")
  })

  test("ignores localhost and reserved", () => {
    const targets = extractTargetsFromCommand("curl http://127.0.0.1/api")
    expect(targets).not.toContain("127.0.0.1")
  })

  test("ignores common non-targets", () => {
    const targets = extractTargetsFromCommand("apt.get install nmap")
    expect(targets).not.toContain("apt.get")
  })

  test("includes .zip and .mov TLDs", () => {
    const targets = extractTargetsFromCommand("nmap target.zip")
    expect(targets).toContain("target.zip")
  })

  test("includes new TLDs like .security", () => {
    const targets = extractTargetsFromCommand("nmap target.security")
    expect(targets).toContain("target.security")
  })

  test("rejects invalid IPs like 999.1.1.1", () => {
    const targets = extractTargetsFromCommand("nmap 999.1.1.1")
    expect(targets).not.toContain("999.1.1.1")
  })

  test("filters filenames", () => {
    const targets = extractTargetsFromCommand("cat output.txt")
    expect(targets).not.toContain("output.txt")
  })

  test("filters .xml .json .conf as filenames", () => {
    const targets = extractTargetsFromCommand("nmap -oX scan.xml -oN results.json --stylesheet report.conf 10.0.0.1")
    expect(targets).not.toContain("scan.xml")
    expect(targets).not.toContain("results.json")
    expect(targets).not.toContain("report.conf")
    expect(targets).toContain("10.0.0.1")
  })

  test("does not extract api.txt as domain (FP regression)", () => {
    const targets = extractTargetsFromCommand("curl http://10.0.0.1/api.txt")
    expect(targets).not.toContain("api.txt")
  })

  test("does not extract wordlist path as domain", () => {
    const targets = extractTargetsFromCommand("gobuster dir -u http://10.0.0.1 -w /usr/share/wordlists/common.txt")
    expect(targets).not.toContain("common.txt")
    expect(targets).not.toContain("wordlists/common.txt")
  })

  test("extracts long TLDs: .company .security .network .agency", () => {
    expect(extractTargetsFromCommand("nmap target.company")).toContain("target.company")
    expect(extractTargetsFromCommand("nmap target.security")).toContain("target.security")
    expect(extractTargetsFromCommand("nmap target.network")).toContain("target.network")
    expect(extractTargetsFromCommand("nmap app.agency")).toContain("app.agency")
  })

  test("extracts two-part domain with standard TLD", () => {
    const targets = extractTargetsFromCommand("nmap corp.kz")
    expect(targets).toContain("corp.kz")
  })

  test("does not extract brew.install, pkg.get", () => {
    expect(extractTargetsFromCommand("brew.install nmap")).not.toContain("brew.install")
    expect(extractTargetsFromCommand("pkg.get update")).not.toContain("pkg.get")
  })

  test("extracts IPv6 addresses", () => {
    const targets = extractTargetsFromCommand("nmap -6 fe80::1")
    expect(targets.some((t) => t.includes("fe80"))).toBe(true)
  })
})

// --- False positive / false negative scenarios from code review ---

describe("scope-check: real-world FP/FN scenarios", () => {
  const bugBountyScope = {
    targets: ["*.example.com"],
    excludes: [],
  }

  test("bug bounty: wildcard does NOT match apex", () => {
    const result = checkScope("example.com", bugBountyScope)
    expect(result.inScope).toBe(false)
  })

  test("bug bounty: wildcard matches subdomain", () => {
    expect(checkScope("app.example.com", bugBountyScope).inScope).toBe(true)
    expect(checkScope("api.example.com", bugBountyScope).inScope).toBe(true)
    expect(checkScope("deep.sub.example.com", bugBountyScope).inScope).toBe(true)
  })

  test("CIDR exclude blocks specific IP", () => {
    const scope = {
      targets: ["10.0.0.0/8"],
      excludes: ["10.0.0.0/24"],
    }
    expect(checkScope("10.0.0.5", scope).inScope).toBe(false)
    expect(checkScope("10.0.1.5", scope).inScope).toBe(true)
  })

  test("case mismatch: domain in different case still matches", () => {
    const scope = {
      targets: ["CORP.EXAMPLE.COM"],
      excludes: [],
    }
    expect(checkScope("corp.example.com", scope).inScope).toBe(true)
    expect(checkScope("Corp.Example.Com", scope).inScope).toBe(true)
  })

  test("URL with port: scope checks extracted host", () => {
    const scope = {
      targets: ["10.0.0.0/24"],
      excludes: [],
    }
    expect(checkScope("http://10.0.0.5:8080/admin", scope).inScope).toBe(true)
    expect(checkScope("https://10.0.1.5:443/", scope).inScope).toBe(false)
  })

  test("invalid IP 999.1.1.1 does not match any CIDR", () => {
    const scope = {
      targets: ["0.0.0.0/0"],
      excludes: [],
    }
    // 999.1.1.1 is not a valid IP, isIp returns false, so it won't try CIDR match
    const result = checkScope("999.1.1.1", scope)
    expect(result.inScope).toBe(false)
  })

  test("IPv6 target in IPv6 CIDR scope", () => {
    const scope = {
      targets: ["fe80::/10"],
      excludes: [],
    }
    expect(checkScope("fe80::1", scope).inScope).toBe(true)
    expect(checkScope("2001:db8::1", scope).inScope).toBe(false)
  })

  test("mixed IPv4/IPv6 scope", () => {
    const scope = {
      targets: ["10.0.0.0/24", "fe80::/10"],
      excludes: [],
    }
    expect(checkScope("10.0.0.5", scope).inScope).toBe(true)
    expect(checkScope("fe80::1", scope).inScope).toBe(true)
    expect(checkScope("192.168.1.1", scope).inScope).toBe(false)
  })

  test("empty scope: everything is not_matched", () => {
    const scope = { targets: [], excludes: [] }
    const result = checkScope("10.0.0.1", scope)
    expect(result.inScope).toBe(false)
    if (!result.inScope) expect(result.reason).toBe("not_matched")
  })

  test("subdomain implicitly in scope via parent domain", () => {
    const scope = {
      targets: ["example.com"],
      excludes: [],
    }
    // isSubdomainOf matches sub.example.com against example.com
    expect(checkScope("sub.example.com", scope).inScope).toBe(true)
    // but example.com itself only matches via exact match
    expect(checkScope("example.com", scope).inScope).toBe(true)
  })
})

describe("extractTargetsFromCommand: FP-prone commands", () => {
  test("nmap with output flags does not extract filenames as targets", () => {
    const targets = extractTargetsFromCommand("nmap -sV -oX /tmp/scan.xml -oN /tmp/scan.txt 10.0.0.1")
    expect(targets).toContain("10.0.0.1")
    expect(targets).not.toContain("scan.xml")
    expect(targets).not.toContain("scan.txt")
  })

  test("curl downloading tool does not flag github.com", () => {
    const targets = extractTargetsFromCommand("curl -L https://github.com/tool/releases/download/v1.0/tool.tar.gz -o tool.tar.gz")
    expect(targets).not.toContain("github.com")
    expect(targets).not.toContain("tool.tar.gz")
  })

  test("python script with target IP extracts only the IP", () => {
    const targets = extractTargetsFromCommand("python3 exploit.py 10.0.0.1")
    expect(targets).toContain("10.0.0.1")
    expect(targets).not.toContain("exploit.py")
  })

  test("netexec with domain target", () => {
    const targets = extractTargetsFromCommand("netexec smb dc01.corp.local -u admin -p 'P@ssw0rd'")
    expect(targets).toContain("dc01.corp.local")
  })

  test("gobuster with wordlist path", () => {
    const targets = extractTargetsFromCommand("gobuster dir -u http://10.0.0.1 -w /usr/share/wordlists/directory-list-2.3-medium.txt")
    expect(targets).toContain("10.0.0.1")
    expect(targets.some((t) => t.includes("wordlists") || t.includes("medium.txt"))).toBe(false)
  })

  test("sqlmap with URL target", () => {
    const targets = extractTargetsFromCommand("sqlmap -u 'http://10.0.0.1/page?id=1' --batch")
    expect(targets).toContain("10.0.0.1")
  })

  test("nikto scan", () => {
    const targets = extractTargetsFromCommand("nikto -h 10.0.0.1 -p 8080 -o /tmp/nikto.html")
    expect(targets).toContain("10.0.0.1")
    expect(targets).not.toContain("nikto.html")
  })

  test("multiple targets in single command", () => {
    const targets = extractTargetsFromCommand("nmap -sV 10.0.0.1 10.0.0.2 192.168.1.0/24")
    expect(targets).toContain("10.0.0.1")
    expect(targets).toContain("10.0.0.2")
    expect(targets).toContain("192.168.1.0/24")
  })

  test("PGPASSWORD in env does not extract as domain", () => {
    const targets = extractTargetsFromCommand("PGPASSWORD='secret' psql -h 10.0.0.1 -U admin -c 'SELECT 1'")
    expect(targets).toContain("10.0.0.1")
    // "secret" and "admin" should not appear as targets
    expect(targets.length).toBe(1)
  })
})
