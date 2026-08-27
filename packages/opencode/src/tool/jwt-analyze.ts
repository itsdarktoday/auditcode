import { createHmac } from "node:crypto"
import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./jwt-analyze.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  token: Schema.String.annotate({
    description: "The JWT token to analyze",
  }),
  host_ip: Schema.optional(Schema.String).annotate({
    description: "Host IP to bind vulnerability to in engagement state",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Auto-update engagement state with weaknesses (default: true)",
  }),
})

interface Weakness {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  detail: string
}

const COMMON_SECRETS = [
  "secret",
  "password",
  "key",
  "123456",
  "admin",
  "test",
  "jwt_secret",
  "changeme",
  "supersecret",
  "default",
  "qwerty",
  "letmein",
  "jwt",
  "token",
  "s3cr3t",
  "",
]

function base64UrlDecode(input: string): string {
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/")
  const pad = base64.length % 4
  if (pad === 2) base64 += "=="
  else if (pad === 3) base64 += "="
  return Buffer.from(base64, "base64").toString("utf-8")
}

function tryDecodeJson(segment: string): Record<string, unknown> | null {
  try {
    return JSON.parse(base64UrlDecode(segment))
  } catch {
    return null
  }
}

function checkWeakSecret(token: string, header: Record<string, unknown>): Weakness | null {
  const alg = String(header.alg ?? "").toUpperCase()
  if (!alg.startsWith("HS")) return null

  const parts = token.split(".")
  if (parts.length < 3) return null

  const signingInput = `${parts[0]}.${parts[1]}`
  const signature = parts[2]!

  const algMap: Record<string, string> = {
    HS256: "sha256",
    HS384: "sha384",
    HS512: "sha512",
  }
  const hashAlg = algMap[alg]
  if (!hashAlg) return null

  for (const secret of COMMON_SECRETS) {
    const computed = createHmac(hashAlg, secret)
      .update(signingInput)
      .digest("base64url")

    if (computed === signature) {
      return {
        id: "weak-secret",
        title: `Weak HMAC Secret: "${secret || "(empty string)"}"`,
        severity: "critical",
        detail: `Token signed with ${alg} using a weak/common secret: "${secret || "(empty)"}". Anyone can forge tokens.`,
      }
    }
  }
  return null
}

function analyzeToken(token: string): {
  header: Record<string, unknown> | null
  payload: Record<string, unknown> | null
  weaknesses: Weakness[]
  overallSeverity: "critical" | "high" | "medium" | "low" | "info"
} {
  const weaknesses: Weakness[] = []
  const parts = token.trim().split(".")

  if (parts.length < 2) {
    return {
      header: null,
      payload: null,
      weaknesses: [{ id: "malformed", title: "Malformed JWT", severity: "info", detail: `Expected 3 dot-separated parts, got ${parts.length}` }],
      overallSeverity: "info",
    }
  }

  const header = tryDecodeJson(parts[0]!)
  const payload = tryDecodeJson(parts[1]!)

  if (!header) {
    weaknesses.push({ id: "bad-header", title: "Invalid JWT Header", severity: "info", detail: "Could not decode header as JSON" })
  }

  if (!payload) {
    weaknesses.push({ id: "bad-payload", title: "Invalid JWT Payload", severity: "info", detail: "Could not decode payload as JSON" })
  }

  if (header) {
    const alg = String(header.alg ?? "").toLowerCase()

    if (alg === "none" || alg === "") {
      weaknesses.push({
        id: "alg-none",
        title: "Algorithm None Attack",
        severity: "critical",
        detail: `JWT header specifies alg:"${header.alg}". Token can be forged without any secret.`,
      })
    }

    if (alg.startsWith("hs") && header.typ === "JWT") {
      const secretResult = checkWeakSecret(token, header)
      if (secretResult) weaknesses.push(secretResult)
    }

    if (!header.kid && !header.jku && !header.x5u) {
      // No key identifier — not necessarily a weakness, but worth noting
    }

    if (header.jku) {
      weaknesses.push({
        id: "jku-present",
        title: "JKU Header Present",
        severity: "medium",
        detail: `JKU (JWK Set URL): ${header.jku}. If server fetches keys from this URL, it may be vulnerable to SSRF or key injection.`,
      })
    }

    if (header.x5u) {
      weaknesses.push({
        id: "x5u-present",
        title: "X5U Header Present",
        severity: "medium",
        detail: `X5U (X.509 URL): ${header.x5u}. Server may fetch certificates from attacker-controlled URL.`,
      })
    }
  }

  if (payload) {
    const now = Math.floor(Date.now() / 1000)

    if (payload.exp !== undefined) {
      const exp = Number(payload.exp)
      if (exp < now) {
        weaknesses.push({
          id: "expired",
          title: "Expired Token",
          severity: "low",
          detail: `Token expired at ${new Date(exp * 1000).toISOString()}. If server still accepts it, expiration is not enforced.`,
        })
      }
    } else {
      weaknesses.push({
        id: "no-exp",
        title: "Missing Expiration Claim",
        severity: "medium",
        detail: "No 'exp' claim — token never expires. If compromised, it's valid forever.",
      })
    }

    if (payload.iat === undefined) {
      weaknesses.push({
        id: "no-iat",
        title: "Missing Issued-At Claim",
        severity: "low",
        detail: "No 'iat' claim — cannot determine token age for replay detection.",
      })
    }

    if (payload.iss === undefined) {
      weaknesses.push({
        id: "no-iss",
        title: "Missing Issuer Claim",
        severity: "low",
        detail: "No 'iss' claim — server may not validate token origin, enabling cross-service token reuse.",
      })
    }

    if (payload.sub === undefined) {
      weaknesses.push({
        id: "no-sub",
        title: "Missing Subject Claim",
        severity: "info",
        detail: "No 'sub' claim — token doesn't bind to a specific user/entity.",
      })
    }

    const hasAdmin = Object.entries(payload).some(([k, v]) => {
      const key = k.toLowerCase()
      return (key === "admin" || key === "is_admin" || key === "role") &&
        (v === true || v === "admin" || v === "root" || v === "superadmin")
    })
    if (hasAdmin) {
      weaknesses.push({
        id: "admin-claim",
        title: "Admin/Privileged Claims in Token",
        severity: "high",
        detail: "Token contains admin/privileged role claims. If algorithm is weak, attacker can elevate privileges by forging token.",
      })
    }
  }

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const overallSeverity = weaknesses.length === 0
    ? "info" as const
    : weaknesses.reduce((worst, w) => (severityOrder[w.severity]! < severityOrder[worst.severity]! ? w : worst)).severity

  return { header, payload, weaknesses, overallSeverity }
}

export const JwtAnalyzeTool = Tool.define(
  "jwt_analyze",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: { token: string; host_ip?: string; auto_update?: boolean },
        _ctx: Tool.Context,
      ) =>
        Effect.gen(function* () {
          const shouldUpdate = params.auto_update !== false
          const result = analyzeToken(params.token)

          const lines: string[] = []
          lines.push("JWT Analysis")
          lines.push("")

          if (result.header) {
            lines.push("Header:")
            lines.push(`  ${JSON.stringify(result.header, null, 2).split("\n").join("\n  ")}`)
            lines.push("")
          }

          if (result.payload) {
            lines.push("Payload:")
            lines.push(`  ${JSON.stringify(result.payload, null, 2).split("\n").join("\n  ")}`)
            lines.push("")
          }

          if (result.weaknesses.length === 0) {
            lines.push("No weaknesses detected.")
          } else {
            lines.push(`Weaknesses Found (${result.weaknesses.length}):`)
            lines.push("")
            for (const w of result.weaknesses) {
              lines.push(`  [${w.severity.toUpperCase()}] ${w.title}`)
              lines.push(`    ${w.detail}`)
              lines.push("")
            }
          }

          lines.push(`Overall Risk: ${result.overallSeverity.toUpperCase()}`)

          const hasVuln = result.weaknesses.some((w) =>
            w.severity === "critical" || w.severity === "high" || w.severity === "medium",
          )

          if (shouldUpdate && hasVuln && params.host_ip) {
            const state = yield* store.get()
            yield* store.addHost(params.host_ip, { ip: params.host_ip })

            const topWeakness = result.weaknesses.reduce((worst, w) => {
              const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
              return (order[w.severity]! < order[worst.severity]!) ? w : worst
            })

            const vulnTitle = `JWT Weakness: ${topWeakness.title}`
            const evidenceStr = result.weaknesses.map((w) => `[${w.severity}] ${w.title}: ${w.detail}`).join("\n")

            yield* store.addVuln(params.host_ip, {
              id: `jwt-${topWeakness.id}-${Date.now()}`,
              title: vulnTitle,
              severity: result.overallSeverity === "info" ? "low" : result.overallSeverity,
              status: "confirmed",
              confidence: result.overallSeverity === "critical" ? 0.95 : 0.85,
              description: `JWT token weaknesses found: ${result.weaknesses.map((w) => w.title).join(", ")}.`,
              evidence: evidenceStr,
              evidence_items: [{
                tool: "jwt_analyze",
                output: evidenceStr,
                timestamp: new Date().toISOString(),
                confidence: result.overallSeverity === "critical" ? 0.95 : 0.85,
              }],
              references: [],
            })

            const updatedState = yield* store.get()
            if (updatedState) yield* store.save(updatedState)

            if (state) {
              yield* events.publish(PentestEvent.VulnFound, {
                timestamp: Date.now(),
                engagementID: state.id,
                hostIp: params.host_ip,
                title: vulnTitle,
                severity: result.overallSeverity === "info" ? "low" : result.overallSeverity,
                status: "confirmed",
              })
            }

            lines.push("")
            lines.push(`[Auto-updated engagement state: ${vulnTitle} on ${params.host_ip}]`)
          }

          return {
            title: `jwt: ${result.weaknesses.length} weakness${result.weaknesses.length !== 1 ? "es" : ""}`,
            metadata: {
              weaknesses: result.weaknesses.length,
              overall_severity: result.overallSeverity,
              algorithm: result.header?.alg ?? "unknown",
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)
