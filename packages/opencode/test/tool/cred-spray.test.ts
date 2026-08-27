import { describe, expect, test } from "bun:test"
import { shq, buildCommand, isNtlmHash } from "@/tool/cred-spray"

describe("shq (shell quoting)", () => {
  test("wraps in single quotes", () => {
    expect(shq("normal")).toBe("'normal'")
  })

  test("escapes single quotes", () => {
    expect(shq("pass'word")).toBe("'pass'\\''word'")
  })

  test("multiple single quotes", () => {
    expect(shq("it's a test's")).toBe("'it'\\''s a test'\\''s'")
  })

  test("empty string", () => {
    expect(shq("")).toBe("''")
  })

  test("special chars preserved", () => {
    expect(shq("$(rm -rf /)")).toBe("'$(rm -rf /)'")
    expect(shq("`whoami`")).toBe("'`whoami`'")
    expect(shq("a;b&&c|d")).toBe("'a;b&&c|d'")
  })
})

describe("isNtlmHash", () => {
  test("valid LM:NT hash", () => {
    expect(isNtlmHash("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")).toBe(true)
  })

  test("valid NT-only hash", () => {
    expect(isNtlmHash("31d6cfe0d16ae931b73c59d7e0c089c0")).toBe(true)
  })

  test("password that looks like hash", () => {
    expect(isNtlmHash("abcdef0123456789abcdef0123456789")).toBe(true)
  })

  test("non-hash password", () => {
    expect(isNtlmHash("MyP@ssw0rd123")).toBe(false)
    expect(isNtlmHash("short")).toBe(false)
    expect(isNtlmHash("")).toBe(false)
  })
})

describe("buildCommand", () => {
  test("smb with password on default port", () => {
    const cmd = buildCommand("smb", "10.0.0.1", 445, "admin", "password123", false)
    expect(cmd).toContain("netexec smb")
    expect(cmd).toContain("-p 'password123'")
    expect(cmd).not.toContain("--port")
  })

  test("smb with hash", () => {
    const cmd = buildCommand("smb", "10.0.0.1", 445, "admin", "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", true)
    expect(cmd).toContain("-H ")
    expect(cmd).not.toContain("-p ")
  })

  test("smb on non-standard port", () => {
    const cmd = buildCommand("smb", "10.0.0.1", 4455, "admin", "pass", false)
    expect(cmd).toContain("--port 4455")
  })

  test("mysql includes port", () => {
    const cmd = buildCommand("mysql", "10.0.0.1", 3307, "root", "pass", false)
    expect(cmd).toContain("-P 3307")
  })

  test("postgresql includes port", () => {
    const cmd = buildCommand("postgresql", "10.0.0.1", 5433, "postgres", "pass", false)
    expect(cmd).toContain("-p 5433")
  })

  test("web uses https for 443", () => {
    const cmd = buildCommand("web", "10.0.0.1", 443, "admin", "pass", false)
    expect(cmd).toContain("https://")
  })

  test("web uses https for 8443", () => {
    const cmd = buildCommand("web", "10.0.0.1", 8443, "admin", "pass", false)
    expect(cmd).toContain("https://")
  })

  test("web uses http for 80", () => {
    const cmd = buildCommand("web", "10.0.0.1", 80, "admin", "pass", false)
    expect(cmd).toContain("http://")
    expect(cmd).not.toContain("https://")
  })

  test("web uses http for 8080", () => {
    const cmd = buildCommand("web", "10.0.0.1", 8080, "admin", "pass", false)
    expect(cmd).toContain("http://")
  })

  test("shell injection in username is quoted", () => {
    const cmd = buildCommand("smb", "10.0.0.1", 445, "'; rm -rf /; echo '", "pass", false)
    // The single quotes in the injected string get escaped, making the whole thing a single argument
    expect(cmd).toContain("'\\''")
    // Verify the username is properly wrapped (starts and ends with shq delimiters)
    expect(cmd).toContain("-u '")
  })

  test("shell injection in password is quoted", () => {
    const cmd = buildCommand("ssh", "10.0.0.1", 22, "user", "$(whoami)", false)
    expect(cmd).toContain("'$(whoami)'")
  })

  test("ftp includes port", () => {
    const cmd = buildCommand("ftp", "10.0.0.1", 2121, "anon", "pass", false)
    expect(cmd).toContain(":2121/")
  })

  test("password with single quote is safely escaped", () => {
    const cmd = buildCommand("smb", "10.0.0.1", 445, "admin", "pass'word", false)
    // Must not produce broken quoting: -p 'pass'word' (would break shell)
    // Must produce: -p 'pass'\''word'
    expect(cmd).toContain("'pass'\\''word'")
    expect(cmd).not.toContain("-p 'pass'word'")
  })

  test("password with shell injection attempt is neutered", () => {
    const cmd = buildCommand("ssh", "10.0.0.1", 22, "admin", "'; rm -rf ~ #", false)
    // The entire value should be a single quoted argument
    const escaped = shq("'; rm -rf ~ #")
    expect(cmd).toContain(escaped)
  })

  test("username O'Brien is safely quoted", () => {
    const cmd = buildCommand("winrm", "10.0.0.1", 5985, "O'Brien", "password", false)
    expect(cmd).toContain("'O'\\''Brien'")
  })

  test("PGPASSWORD with quotes does not break env assignment", () => {
    const cmd = buildCommand("postgresql", "10.0.0.1", 5432, "admin", "pass'word", false)
    expect(cmd).toContain("PGPASSWORD='pass'\\''word'")
  })

  test("curl ftp with colon in password is safely quoted", () => {
    const cmd = buildCommand("ftp", "10.0.0.1", 21, "admin", "pass:word'test", false)
    // The u:p pair is quoted together
    expect(cmd).toContain(shq("admin:pass:word'test"))
  })

  test("host with special chars is quoted", () => {
    const cmd = buildCommand("smb", "dc01.corp.local", 445, "admin", "pass", false)
    expect(cmd).toContain("'dc01.corp.local'")
  })

  test("web on port 80 uses http and includes port", () => {
    const cmd = buildCommand("web", "10.0.0.1", 80, "admin", "pass", false)
    expect(cmd).toMatch(/http:\/\/.*:80\//)
    expect(cmd).not.toContain("https://")
  })

  test("web on port 9090 uses http", () => {
    const cmd = buildCommand("web", "10.0.0.1", 9090, "admin", "pass", false)
    expect(cmd).toContain("http://")
    expect(cmd).toContain(":9090/")
  })
})
