import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./xss-detect.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  url: Schema.String.annotate({
    description: "The URL that was tested",
  }),
  parameter: Schema.String.annotate({
    description: "The parameter name that was tested for XSS",
  }),
  request_output: Schema.String.annotate({
    description: "The HTTP response body and/or headers captured after injecting the payload",
  }),
  payload: Schema.optional(Schema.String).annotate({
    description: "The XSS payload that was injected (e.g. <script>alert(1)</script>)",
  }),
  auto_update: Schema.optional(Schema.Boolean).annotate({
    description: "Auto-update engagement state with findings (default: true)",
  }),
})

type XssClassification = "reflected" | "potential_stored" | "blocked" | "not_vulnerable"

interface XssResult {
  classification: XssClassification
  severity: "high" | "medium" | "low" | "info"
  evidence: string[]
  headers: {
    contentType?: string
    xssProtection?: string
    csp?: string
  }
  wafDetected: boolean
  payloadReflected: boolean
  payloadEscaped: boolean
}

function extractHostFromUrl(url: string): { ip: string; port: number } {
  try {
    const parsed = new URL(url)
    const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80
    return { ip: parsed.hostname, port }
  } catch {
    const match = /(?:https?:\/\/)?([^:/]+)(?::(\d+))?/.exec(url)
    if (match) {
      return { ip: match[1]!, port: match[2] ? Number(match[2]) : 80 }
    }
    return { ip: "unknown", port: 80 }
  }
}

const WAF_SIGNATURES = [
  /403 forbidden/i,
  /access denied/i,
  /request blocked/i,
  /web application firewall/i,
  /cloudflare/i,
  /mod_security/i,
  /akamai/i,
  /imperva/i,
  /sucuri/i,
  /aws waf/i,
  /barracuda/i,
  /f5 big-ip/i,
]

const HTML_ESCAPE_MAP: Record<string, string> = {
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "&": "&amp;",
}

function escapeForCheck(payload: string): string {
  let escaped = payload
  for (const [char, entity] of Object.entries(HTML_ESCAPE_MAP)) {
    escaped = escaped.replaceAll(char, entity)
  }
  return escaped
}

function extractHeaders(output: string): XssResult["headers"] {
  const headers: XssResult["headers"] = {}

  const ctMatch = /content-type:\s*([^\r\n]+)/i.exec(output)
  if (ctMatch) headers.contentType = ctMatch[1]!.trim()

  const xssMatch = /x-xss-protection:\s*([^\r\n]+)/i.exec(output)
  if (xssMatch) headers.xssProtection = xssMatch[1]!.trim()

  const cspMatch = /content-security-policy:\s*([^\r\n]+)/i.exec(output)
  if (cspMatch) headers.csp = cspMatch[1]!.trim()

  return headers
}

function analyze(params: {
  url: string
  parameter: string
  request_output: string
  payload?: string
}): XssResult {
  const output = params.request_output
  const evidence: string[] = []
  const headers = extractHeaders(output)

  const wafDetected = WAF_SIGNATURES.some((sig) => sig.test(output))
  if (wafDetected) {
    evidence.push("WAF/filter signature detected in response")
  }

  const defaultPayload = params.payload ?? "<script>alert(1)</script>"
  const payloadReflected = output.includes(defaultPayload)
  const escapedPayload = escapeForCheck(defaultPayload)
  const payloadEscaped = !payloadReflected && output.includes(escapedPayload)

  if (payloadReflected) {
    evidence.push(`Payload reflected unescaped in response: "${defaultPayload}"`)
  } else if (payloadEscaped) {
    evidence.push(`Payload reflected but HTML-escaped: "${escapedPayload}"`)
  }

  if (headers.contentType) {
    const isHtml = /text\/html/i.test(headers.contentType)
    if (isHtml) {
      evidence.push(`Content-Type: ${headers.contentType} (HTML context — XSS payload will render)`)
    } else {
      evidence.push(`Content-Type: ${headers.contentType} (non-HTML — reduced XSS impact)`)
    }
  }

  if (headers.xssProtection) {
    if (/^0/.test(headers.xssProtection)) {
      evidence.push(`X-XSS-Protection: ${headers.xssProtection} (DISABLED — browser XSS filter off)`)
    } else if (/^1/.test(headers.xssProtection)) {
      evidence.push(`X-XSS-Protection: ${headers.xssProtection} (enabled)`)
    }
  }

  if (headers.csp) {
    const hasScriptSrc = /script-src/i.test(headers.csp)
    const allowsUnsafeInline = /unsafe-inline/i.test(headers.csp)
    if (hasScriptSrc && !allowsUnsafeInline) {
      evidence.push(`CSP present with script-src (blocks inline scripts)`)
    } else if (allowsUnsafeInline) {
      evidence.push(`CSP allows 'unsafe-inline' — inline scripts permitted`)
    } else if (!hasScriptSrc) {
      evidence.push(`CSP present but no script-src directive`)
    }
  } else {
    evidence.push("No Content-Security-Policy header")
  }

  let classification: XssClassification
  let severity: "high" | "medium" | "low" | "info"

  if (wafDetected && !payloadReflected) {
    classification = "blocked"
    severity = "info"
    evidence.push("Classification: blocked — WAF prevented payload reflection")
  } else if (payloadReflected) {
    classification = "reflected"
    severity = headers.csp && /script-src/i.test(headers.csp) && !/unsafe-inline/i.test(headers.csp)
      ? "medium"
      : "high"
    evidence.push(`Classification: reflected XSS — payload "${defaultPayload}" found unescaped in response`)
  } else if (payloadEscaped) {
    classification = "not_vulnerable"
    severity = "info"
    evidence.push("Classification: not vulnerable — payload was HTML-escaped")
  } else {
    const hasFormOrInput = /<form|<input|<textarea/i.test(output)
    const http2xx = /HTTP\/\d\.\d\s+2\d{2}/.test(output) || !(/HTTP\/\d/.test(output))
    if (hasFormOrInput && http2xx) {
      classification = "potential_stored"
      severity = "medium"
      evidence.push("Classification: potential stored XSS — input accepted (no immediate reflection, check other pages)")
    } else {
      classification = "not_vulnerable"
      severity = "info"
      evidence.push("Classification: not vulnerable — no payload reflection detected")
    }
  }

  return {
    classification,
    severity,
    evidence,
    headers,
    wafDetected,
    payloadReflected,
    payloadEscaped,
  }
}

export const XssDetectTool = Tool.define(
  "xss_detect",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          url: string
          parameter: string
          request_output: string
          payload?: string
          auto_update?: boolean
        },
        _ctx: Tool.Context,
      ) =>
        Effect.gen(function* () {
          const shouldUpdate = params.auto_update !== false
          const result = analyze(params)
          const { ip, port } = extractHostFromUrl(params.url)

          const lines: string[] = []
          lines.push(`XSS Analysis: ${params.url}`)
          lines.push(`Parameter: ${params.parameter}`)
          lines.push(`Payload: ${params.payload ?? "<script>alert(1)</script>"}`)
          lines.push(`Classification: ${result.classification.toUpperCase()}`)
          lines.push(`Severity: ${result.severity.toUpperCase()}`)
          lines.push("")
          lines.push("Evidence:")
          for (const e of result.evidence) {
            lines.push(`  - ${e}`)
          }

          const isVuln = result.classification === "reflected" || result.classification === "potential_stored"

          if (shouldUpdate && isVuln && ip !== "unknown") {
            const state = yield* store.get()
            yield* store.addHost(ip, { ip })

            const xssType = result.classification === "reflected" ? "Reflected" : "Potential Stored"
            const vulnTitle = `XSS (${xssType}): ${params.parameter}`
            const evidenceStr = result.evidence.join("\n")

            yield* store.addVuln(ip, {
              id: `xss-${params.parameter}-${Date.now()}`,
              title: vulnTitle,
              severity: result.severity,
              status: result.classification === "reflected" ? "confirmed" : "suspected",
              confidence: result.classification === "reflected" ? 0.9 : 0.6,
              description: `${xssType} XSS via parameter "${params.parameter}" at ${params.url}.`,
              evidence: evidenceStr,
              evidence_items: [{
                tool: "xss_detect",
                command: `curl/browser test on ${params.url} param=${params.parameter}`,
                output: evidenceStr,
                timestamp: new Date().toISOString(),
                confidence: result.classification === "reflected" ? 0.9 : 0.6,
              }],
              service_port: port || undefined,
              references: [],
            })

            const updatedState = yield* store.get()
            if (updatedState) yield* store.save(updatedState)

            if (state) {
              yield* events.publish(PentestEvent.VulnFound, {
                timestamp: Date.now(),
                engagementID: state.id,
                hostIp: ip,
                title: vulnTitle,
                severity: result.severity,
                status: result.classification === "reflected" ? "confirmed" : "suspected",
              })
            }

            lines.push("")
            lines.push(`[Auto-updated engagement state: ${vulnTitle} on ${ip}]`)
          } else if (!isVuln) {
            lines.push("")
            lines.push("[No vulnerability detected — state not updated]")
          }

          if (isVuln) {
            lines.push("")
            lines.push(`[Auto-critic] XSS finding on ${params.parameter} should be validated. Spawn "critic" to confirm exploitability.`)
          }

          return {
            title: `xss: ${result.classification}`,
            metadata: {
              classification: result.classification,
              severity: result.severity,
              waf_detected: result.wafDetected,
              payload_reflected: result.payloadReflected,
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)
