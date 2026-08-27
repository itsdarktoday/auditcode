export * as CommandRisk from "./command-risk"

export type RiskTier = "passive" | "active" | "exploit" | "destructive"

export interface Classification {
  readonly tier: RiskTier
  readonly commands: string[]
  readonly reason?: string
}

const PASSIVE_COMMANDS = new Set([
  "cat", "ls", "dir", "head", "tail", "less", "more", "wc", "sort", "uniq",
  "grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "locate", "which",
  "whereis", "file", "stat", "readlink", "realpath", "basename", "dirname",
  "strings", "xxd", "hexdump", "od", "base64", "sha256sum", "sha1sum", "md5sum",
  "diff", "cmp", "comm", "cut", "paste", "tr", "sed", "awk", "jq", "yq",
  "xargs", "tee", "printf", "echo", "env", "printenv", "set", "export",
  "id", "whoami", "hostname", "uname", "uptime", "date", "cal",
  "pwd", "cd", "pushd", "popd", "mkdir", "touch", "cp", "mv", "ln",
  "tar", "gzip", "gunzip", "bzip2", "xz", "zip", "unzip", "7z",
  "python", "python3", "ruby", "perl", "node", "bun", "php",
  "pip", "pip3", "gem", "npm", "cargo", "go",
  "git", "svn", "hg",
  "man", "help", "info", "type", "alias",
  "openssl", "certutil",
  "ip", "ifconfig", "route", "netstat", "ss", "arp",
  "ps", "top", "htop", "free", "df", "du", "lsof", "strace", "ltrace",
])

const ACTIVE_COMMANDS = new Set([
  "nmap", "masscan", "rustscan", "unicornscan",
  "ping", "traceroute", "tracert", "mtr", "arping", "fping", "hping3",
  "dig", "nslookup", "host", "whois", "dnsrecon", "dnsenum", "fierce", "amass", "subfinder", "assetfinder",
  "curl", "wget", "httpie", "http",
  "nikto", "gobuster", "ffuf", "feroxbuster", "dirsearch", "dirb", "wfuzz",
  "sqlmap", "nosqlmap",
  "nuclei", "whatweb", "wappalyzer", "wafw00f",
  "netexec", "nxc", "crackmapexec", "cme",
  "enum4linux", "enum4linux-ng",
  "smbclient", "smbmap", "smbget",
  "rpcclient", "rpcinfo",
  "ldapsearch", "ldapdomaindump",
  "snmpwalk", "snmpget", "snmpbulkwalk", "onesixtyone",
  "showmount", "rpcbind",
  "ftp", "tftp", "telnet", "nc", "ncat", "netcat",
  "ssh", "scp", "sftp",
  "hydra", "medusa", "patator", "crowbar", "spray",
  "john", "hashcat", "hashid", "hash-identifier",
  "kerbrute", "getTGT.py", "getNPUsers.py", "GetUserSPNs.py",
  "bloodhound-python", "bloodhound",
  "responder",
  "nbtscan", "nmblookup",
  "ike-scan",
  "testssl.sh", "sslscan", "sslyze",
  "smtp-user-enum", "vrfy",
  "finger", "rlogin", "rsh", "rexec",
  "xfreerdp", "rdesktop",
  "wpscan", "joomscan", "droopescan",
  "theHarvester", "recon-ng", "spiderfoot", "maltego",
  "exiftool", "metagoofil",
  "tcpdump", "tshark", "wireshark",
])

const EXPLOIT_COMMANDS = new Set([
  "msfconsole", "msfvenom", "msfdb",
  "metasploit",
  "psexec.py", "wmiexec.py", "smbexec.py", "atexec.py", "dcomexec.py",
  "secretsdump.py", "mimikatz", "pypykatz",
  "evil-winrm",
  "impacket-psexec", "impacket-wmiexec", "impacket-smbexec", "impacket-atexec",
  "impacket-dcomexec", "impacket-secretsdump",
  "chisel", "ligolo", "ligolo-ng",
  "socat",
  "pth-winexe", "pth-smbclient", "pth-rpcclient",
  "proxychains", "proxychains4",
  "sshuttle",
  "ettercap", "bettercap", "arpspoof",
  "beef-xss", "beef",
  "searchsploit",
  "pwntools",
  "ropgadget", "ropper",
  "gdb", "radare2", "r2", "ghidra",
])

const DESTRUCTIVE_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\brm\s+(-[^\s]*r[^\s]*\s+(-[^\s]*f|\/)|\s*-[^\s]*f[^\s]*\s+(-[^\s]*r|\/)|\/\s)/, reason: "recursive force delete" },
  { pattern: /\brm\s+(-rf|-fr)\s+\/(?!\w)/, reason: "recursive delete from root" },
  { pattern: /\bdd\b.*\bof=\/dev\//, reason: "raw disk write" },
  { pattern: /\bmkfs\b/, reason: "filesystem format" },
  { pattern: /\bfdisk\b/, reason: "partition table modification" },
  { pattern: /\bparted\b/, reason: "partition modification" },
  { pattern: /\bwipefs\b/, reason: "filesystem signature wipe" },
  { pattern: /\bshred\b/, reason: "secure file destruction" },
  { pattern: /\bshutdown\b/, reason: "system shutdown" },
  { pattern: /\breboot\b/, reason: "system reboot" },
  { pattern: /\binit\s+[06]\b/, reason: "system halt/reboot" },
  { pattern: /\bsystemctl\s+(poweroff|reboot|halt)\b/, reason: "system power control" },
  { pattern: /\biptables\s+-F\b/, reason: "flush all firewall rules" },
  { pattern: /\bnft\s+flush\b/, reason: "flush all firewall rules" },
  { pattern: /:\(\)\s*\{\s*:\|:&\s*\}\s*;?\s*:/, reason: "fork bomb" },
  { pattern: />\s*\/dev\/sd[a-z]/, reason: "raw disk overwrite" },
  { pattern: /\bchmod\s+(-R\s+)?777\s+\/(?!\w)/, reason: "recursive world-writable from root" },
  { pattern: /\bchown\s+-R\b.*\/(?!\w)/, reason: "recursive ownership change from root" },
]

function extractCommandNames(command: string): string[] {
  const segments = command
    .split(/[;|&\n]+/)
    .map((s) => s.trim())
    .filter(Boolean)

  const names: string[] = []
  for (const segment of segments) {
    let cleaned = segment
      .replace(/^\s*(?:sudo|doas|env|time|timeout|nice|strace|ltrace|nohup|setsid)\s+/g, "")
      .replace(/^\s*[A-Z_]+=\S*\s+/g, "")
      .trim()

    if (!cleaned) continue

    const tokens = cleaned.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)
    if (!tokens?.[0]) continue

    let cmd = tokens[0].replace(/^['"]|['"]$/g, "")

    if (cmd.includes("/")) {
      cmd = cmd.split("/").pop() ?? cmd
    }

    if (cmd === "sudo" || cmd === "doas") {
      cmd = tokens[1]?.replace(/^['"]|['"]$/g, "") ?? cmd
    }

    names.push(cmd)
  }
  return names
}

export function classify(command: string): Classification {
  for (const { pattern, reason } of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(command)) {
      return {
        tier: "destructive",
        commands: extractCommandNames(command),
        reason: `Destructive operation detected: ${reason}`,
      }
    }
  }

  const names = extractCommandNames(command)
  let maxTier: RiskTier = "passive"
  const matched: string[] = []

  for (const cmd of names) {
    if (EXPLOIT_COMMANDS.has(cmd)) {
      maxTier = "exploit"
      matched.push(cmd)
    } else if (ACTIVE_COMMANDS.has(cmd)) {
      if (maxTier === "passive") {
        maxTier = "active"
      }
      matched.push(cmd)
    } else if (PASSIVE_COMMANDS.has(cmd)) {
      matched.push(cmd)
    } else {
      matched.push(cmd)
    }
  }

  return {
    tier: maxTier,
    commands: matched,
    ...(maxTier === "exploit" ? { reason: `Exploitation tool: ${matched.filter((c) => EXPLOIT_COMMANDS.has(c)).join(", ")}` } : {}),
  }
}

export function tierWarning(classification: Classification): string | undefined {
  switch (classification.tier) {
    case "destructive":
      return `BLOCKED — ${classification.reason}. This command can cause irreversible damage. Run it manually if intentional.`
    case "exploit":
      return `EXPLOIT-TIER: ${classification.reason}. Ensure you have explicit authorization for this action.`
    default:
      return undefined
  }
}
