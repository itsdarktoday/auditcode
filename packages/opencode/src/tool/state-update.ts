import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import { ScopeMatcher } from "@auditcode/core/engagement/scope-matcher"
import { PentestEvent } from "@auditcode/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./state-update.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals([
    "batch",
    "add_contract",
    "update_contract",
    "delete_contract",
    "add_invariant",
    "update_invariant",
    "delete_invariant",
    "add_actor_role",
    "update_actor_role",
    "add_poc",
    "update_poc",
    "record_critic_verdict",
    "add_host",
    "delete_host",
    "add_vuln",
    "update_vuln",
    "delete_vuln",
    "add_credential",
    "delete_credential",
    "add_access",
    "set_phase",
    "set_mode",
    "update_scope",
    "add_discovered_target",
    "add_flag",
    "add_note",
    "add_attack_step",
    "create_engagement",
    "load_engagement",
    "reload_engagement",
    "set_domain",
    "update_domain",
    "add_objective",
    "update_objective",
    "complete_objective",
    "add_relationship",
    "delete_relationship",
    "add_decision",
    "update_decision_outcome",
    "add_alert",
    "acknowledge_alert",
    "add_live_session",
    "update_live_session",
    "remove_live_session",
    "record_artifact",
    "add_network_segment",
    "update_network_segment",
    "remove_network_segment",
    "record_wordlist",
    "set_pause",
    "record_vector",
    "set_goal",
    "update_goal",
    "clear_goal",
  ]).annotate({
    description: "The mutation to perform on the engagement state.",
  }),
  data: Schema.Unknown.annotate({
    description: "Action-specific data. See tool description for required fields per action. For batch: {operations: [{action, data}, ...]}",
  }),
})

const NO_ENGAGEMENT = "No engagement loaded. Use create_engagement or load_engagement first."

function countsLine(state: EngagementSchema.State): string {
  const s = EngagementSchema.summary(state)
  const objStr = s.objectives_total > 0 ? ` obj:${s.objectives_completed}/${s.objectives_total}` : ""
  return `[${state.name}] phase:${s.current_phase} hosts:${s.hosts_discovered} vulns:${s.vulnerabilities} creds:${s.credentials} flags:${s.flags}${objStr}`
}

export const StateUpdateTool = Tool.define(
  "state_update",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service
    const executeAction = (params: { action: string; data: unknown }, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
      Effect.gen(function* () {
        const raw = params.data ?? {}
        const d = (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, any>

        switch (params.action) {

          case "add_contract": {
            const name = d.name as string
            if (!name) return { title: "Error", metadata: {}, output: "Error: data.name is required for add_contract." }
            const contractData = {
              name,
              path: d.path ?? `contracts/${name}.sol`,
              sloc: d.sloc,
              proxy_pattern: d.proxy_pattern,
              compiler_version: d.compiler_version,
              inheritance: d.inheritance,
              interfaces_implemented: d.interfaces_implemented,
              state_variables: d.state_variables,
              functions: d.functions,
              modifiers: d.modifiers,
              events: d.events,
              custom_errors: d.custom_errors,
              dependencies: d.dependencies,
              notes: d.notes,
            } as EngagementSchema.ContractInfo
            yield* store.addContract(name, contractData)
            return {
              title: `Added Contract ${name}`,
              metadata: { name },
              output: `Contract ${name} added to scope (${contractData.path}).`,
            }
          }

          case "update_contract": {
            const name = d.name as string
            if (!name) return { title: "Error", metadata: {}, output: "Error: data.name is required for update_contract." }
            const updated = yield* store.updateContract(name, d)
            return {
              title: `Updated Contract ${name}`,
              metadata: { name },
              output: updated ? `Contract ${name} updated successfully.` : `Contract ${name} not found.`,
            }
          }

          case "delete_contract": {
            const name = d.name as string
            if (!name) return { title: "Error", metadata: {}, output: "Error: data.name is required for delete_contract." }
            const deleted = yield* store.deleteContract(name)
            return {
              title: `Deleted Contract ${name}`,
              metadata: { name },
              output: deleted ? `Contract ${name} deleted.` : `Contract ${name} not found.`,
            }
          }

          case "add_invariant": {
            const id = d.id as string ?? `INV-${Date.now().toString().slice(-4)}`
            const title = d.title as string
            if (!title) return { title: "Error", metadata: {}, output: "Error: data.title is required for add_invariant." }
            const inv: EngagementSchema.Invariant = {
              id,
              title,
              description: d.description,
              target_contracts: d.target_contracts,
              status: d.status ?? "untested",
              fuzz_property: d.fuzz_property,
              violation_trace: d.violation_trace,
              notes: d.notes,
            }
            yield* store.addInvariant(inv)
            return {
              title: `Added Invariant ${id}`,
              metadata: { id },
              output: `Invariant ${id}: "${title}" registered.`,
            }
          }

          case "update_invariant": {
            const id = d.id as string
            if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for update_invariant." }
            const updated = yield* store.updateInvariant(id, d)
            return {
              title: `Updated Invariant ${id}`,
              metadata: { id },
              output: updated ? `Invariant ${id} updated.` : `Invariant ${id} not found.`,
            }
          }

          case "delete_invariant": {
            const id = d.id as string
            if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for delete_invariant." }
            const deleted = yield* store.deleteInvariant(id)
            return {
              title: `Deleted Invariant ${id}`,
              metadata: { id },
              output: deleted ? `Invariant ${id} deleted.` : `Invariant ${id} not found.`,
            }
          }

          case "add_actor_role": {
            const role_name = d.role_name as string
            if (!role_name) return { title: "Error", metadata: {}, output: "Error: data.role_name is required for add_actor_role." }
            const role: EngagementSchema.ActorRole = {
              role_name,
              description: d.description,
              privileged_functions: d.privileged_functions,
              timelock_delay: d.timelock_delay,
              multisig_threshold: d.multisig_threshold,
              holders: d.holders,
              notes: d.notes,
            }
            yield* store.addActorRole(role)
            return {
              title: `Added Role ${role_name}`,
              metadata: { role_name },
              output: `Actor Role "${role_name}" added.`,
            }
          }

          case "add_poc": {
            const id = d.id as string ?? `POC-${Date.now().toString().slice(-4)}`
            const name = d.name as string ?? id
            const poc: EngagementSchema.PoCTest = {
              id,
              name,
              target_vuln_id: d.target_vuln_id,
              framework: d.framework ?? "foundry",
              test_file_path: d.test_file_path,
              command: d.command,
              status: d.status ?? "pending",
              execution_trace: d.execution_trace,
              gas_used: d.gas_used,
            }
            yield* store.addPoCTest(poc)
            return {
              title: `Added PoC ${name}`,
              metadata: { id },
              output: `PoC test "${name}" recorded (${poc.status}).`,
            }
          }

          case "record_critic_verdict": {
            const vuln_id = d.vuln_id as string
            const verdict = d.verdict as "validated" | "rejected" | "downgraded"
            const reason = d.reason as string ?? ""
            if (!vuln_id || !verdict) return { title: "Error", metadata: {}, output: "Error: vuln_id and verdict are required." }
            const state = yield* store.get()
            const target = d.contract_name ?? "contract"
            yield* store.updateVuln(target, vuln_id, {
              status: verdict === "rejected" ? "false_positive" : verdict === "validated" ? "confirmed" : "suspected",
              critic_review: {
                verdict,
                reason,
                judging_gate: d.judging_gate ?? "blocks",
                reviewed_by: "critic",
                timestamp: new Date().toISOString(),
              },
            })
            return {
              title: `Critic Verdict: ${verdict.toUpperCase()}`,
              metadata: { vuln_id, verdict },
              output: `Vulnerability ${vuln_id} marked as ${verdict} by critic. Reason: ${reason}`,
            }
          }

          // --- Lifecycle ---
          case "create_engagement": {
              const name = d.name as string
              if (!name) {
                return { title: "Error", metadata: {}, output: "Error: data.name is required for create_engagement." }
              }
              const state = yield* store.create(name)
              return {
                title: `Created ${name}`,
                metadata: { name },
                output: `Engagement "${name}" created (id: ${state.id}). Phase: ${state.current_phase}, Mode: ${state.mode}.`,
              }
            }

            case "load_engagement": {
              const name = d.name as string
              if (!name) {
                return { title: "Error", metadata: {}, output: "Error: data.name is required for load_engagement." }
              }
              const state = yield* store.load(name)
              if (!state) {
                const available = yield* store.listEngagements()
                return {
                  title: "Not Found",
                  metadata: {},
                  output: `Engagement "${name}" not found.${available.length > 0 ? ` Available: ${available.join(", ")}` : ""}`,
                }
              }
              return {
                title: `Loaded ${name}`,
                metadata: { name },
                output: `Engagement "${name}" loaded. ${countsLine(state)}`,
              }
            }

            case "reload_engagement": {
              const current = yield* store.get()
              if (!current) {
                return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              }
              const state = yield* store.load(current.name)
              if (!state) {
                return { title: "Error", metadata: {}, output: `Failed to reload engagement "${current.name}" from disk.` }
              }
              return {
                title: `Reloaded ${current.name}`,
                metadata: {},
                output: `Engagement "${current.name}" reloaded from disk. ${countsLine(state)}`,
              }
            }

            // --- Mutations (require loaded engagement) ---
            case "add_host": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const ip = d.ip as string
              if (!ip) {
                return { title: "Error", metadata: {}, output: "Error: data.ip is required for add_host." }
              }
              if (state.scope.targets.length > 0 && state.mode !== "free") {
                const scopeResult = ScopeMatcher.checkScope(ip, state.scope)
                if (!scopeResult.inScope) {
                  return {
                    title: `Out of scope: ${ip}`,
                    metadata: { out_of_scope: true, ip },
                    output: `Host ${ip} is out of scope (${scopeResult.reason}). Not added to engagement state. Use mode=free to bypass scope checks.`,
                  }
                }
              }
              const hostData: Partial<{ -readonly [K in keyof EngagementSchema.Host]: EngagementSchema.Host[K] }> = {}
              if (d.hostname) hostData.hostname = d.hostname as string
              if (d.os) hostData.os = d.os as string
              if (d.services && Array.isArray(d.services)) {
                hostData.services = d.services as EngagementSchema.Service[]
              }
              const host = yield* store.addHost(ip, hostData)
              const updated = yield* store.get()

              yield* events.publish(PentestEvent.HostDiscovered, {
                timestamp: Date.now(),
                engagementID: state.id,
                ip,
                hostname: host.hostname,
                serviceCount: host.services.length,
              })
              return {
                title: `Host ${ip}`,
                metadata: { ip },
                output: `Host ${ip} added/updated.${host.hostname ? ` hostname:${host.hostname}` : ""}${host.os ? ` os:${host.os}` : ""} services:${host.services.length}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_host": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const ip = d.ip as string
              if (!ip) {
                return { title: "Error", metadata: {}, output: "Error: data.ip is required for delete_host." }
              }
              const deleted = yield* store.deleteHost(ip)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Host ${ip} not found.` }
              }
              const updated = yield* store.get()

              return {
                title: `Deleted ${ip}`,
                metadata: { ip },
                output: `Host ${ip} deleted.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_vuln": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const title = d.title as string
              if (!hostIp || !title) {
                return { title: "Error", metadata: {}, output: "Error: data.host_ip and data.title are required for add_vuln." }
              }
              if (!state.hosts[hostIp]) {
                return { title: "Error", metadata: {}, output: `Error: Host ${hostIp} not found. Add the host first.` }
              }
              const vuln = {
                id: d.id || `vuln-${Date.now()}`,
                title,
                severity: d.severity || "medium",
                status: d.status || "suspected",
                confidence: d.confidence as number | undefined,
                description: d.description || "",
                evidence: d.evidence || "",
                evidence_items: d.evidence_items as EngagementSchema.EvidenceItem[] | undefined,
                service_port: d.service_port,
                references: d.references || [],
                mitre_attack_id: d.mitre_attack_id,
              } as EngagementSchema.Vulnerability
              yield* store.addVuln(hostIp, vuln)
              const updated = yield* store.get()

              yield* events.publish(PentestEvent.VulnFound, {
                timestamp: Date.now(),
                engagementID: state.id,
                hostIp,
                title,
                severity: vuln.severity ?? "medium",
                status: vuln.status ?? "suspected",
              })
              return {
                title: `Vuln: ${title}`,
                metadata: { host_ip: hostIp, severity: vuln.severity },
                output: `Vulnerability added to ${hostIp}: [${(vuln.severity ?? "medium").toUpperCase()}] ${title} (${vuln.status ?? "suspected"})${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_vuln": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const vulnId = d.vuln_id as string
              if (!hostIp || !vulnId) {
                return { title: "Error", metadata: {}, output: "Error: data.host_ip and data.vuln_id are required for update_vuln." }
              }
              const patch: Record<string, unknown> = {}
              if (d.status !== undefined) patch.status = d.status
              if (d.severity !== undefined) patch.severity = d.severity
              if (d.confidence !== undefined) patch.confidence = d.confidence
              if (d.evidence !== undefined) patch.evidence = d.evidence
              if (d.evidence_items !== undefined) patch.evidence_items = d.evidence_items
              if (d.description !== undefined) patch.description = d.description
              if (d.title !== undefined) patch.title = d.title
              const ok = yield* store.updateVuln(hostIp, vulnId, patch as Partial<{ -readonly [K in keyof EngagementSchema.Vulnerability]: EngagementSchema.Vulnerability[K] }>)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Vuln "${vulnId}" not found on host ${hostIp}.` }
              }
              const updated = yield* store.get()

              const changedFields = Object.keys(patch).join(", ")
              return {
                title: `Vuln updated: ${vulnId}`,
                metadata: { host_ip: hostIp, vuln_id: vulnId },
                output: `Vulnerability "${vulnId}" on ${hostIp} updated (${changedFields}).${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_vuln": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const vulnId = d.vuln_id as string
              if (!hostIp || !vulnId) {
                return { title: "Error", metadata: {}, output: "Error: data.host_ip and data.vuln_id are required for delete_vuln." }
              }
              const deleted = yield* store.deleteVuln(hostIp, vulnId)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Vuln "${vulnId}" not found on host ${hostIp}.` }
              }
              const updated = yield* store.get()

              return {
                title: `Vuln deleted: ${vulnId}`,
                metadata: { host_ip: hostIp, vuln_id: vulnId },
                output: `Vulnerability "${vulnId}" deleted from ${hostIp}.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_credential": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              const username = d.username as string
              if (!id || !username) {
                return { title: "Error", metadata: {}, output: "Error: data.id and data.username are required for add_credential." }
              }
              const cred = {
                cred_type: d.cred_type || "password",
                username,
                value: d.value || "",
                source: d.source || "",
                valid_for: d.valid_for || [],
                confidence: d.confidence as number | undefined,
                domain: d.domain as string | undefined,
                ticket_type: d.ticket_type as string | undefined,
                service_principal: d.service_principal as string | undefined,
                ticket_expiry: d.ticket_expiry as string | undefined,
              } as Omit<EngagementSchema.Credential, "id">
              yield* store.addCredential(id, cred)
              const updated = yield* store.get()

              yield* events.publish(PentestEvent.CredentialFound, {
                timestamp: Date.now(),
                engagementID: state.id,
                credId: id,
                username,
                credType: d.cred_type as string || "password",
              })
              return {
                title: `Cred: ${username}`,
                metadata: { id, username },
                output: `Credential added: ${username} (${d.cred_type || "password"}) id:${id}${d.source ? ` source:${d.source}` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_credential": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for delete_credential." }
              }
              const deleted = yield* store.deleteCredential(id)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Credential "${id}" not found.` }
              }
              const updated = yield* store.get()

              return {
                title: `Cred deleted: ${id}`,
                metadata: { id },
                output: `Credential "${id}" deleted.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_access": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const accessType = d.access_type as string
              const username = d.username as string
              if (!hostIp || !accessType || !username) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.host_ip, data.access_type, and data.username are required for add_access.",
                }
              }
              if (!state.hosts[hostIp]) {
                return { title: "Error", metadata: {}, output: `Error: Host ${hostIp} not found. Add the host first.` }
              }
              const access = {
                access_type: accessType,
                username,
                level: d.level || "user",
                confidence: d.confidence as number | undefined,
                credential_id: d.credential_id,
                details: d.details || "",
              } as EngagementSchema.Access
              yield* store.addAccess(hostIp, access)
              const updated = yield* store.get()

              yield* events.publish(PentestEvent.AccessGained, {
                timestamp: Date.now(),
                engagementID: state.id,
                hostIp,
                username,
                level: access.level ?? "user",
                accessType,
              })
              return {
                title: `Access: ${hostIp}`,
                metadata: { host_ip: hostIp, username, level: access.level },
                output: `Access added to ${hostIp}: ${accessType} as ${username} (${access.level ?? "user"})${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "set_phase": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const phase = d.phase as EngagementSchema.PentestPhase
              if (!phase) {
                return { title: "Error", metadata: {}, output: "Error: data.phase is required for set_phase." }
              }
              const oldPhase = state.current_phase
              yield* store.setPhase(phase)
              const updated = yield* store.get()

              yield* events.publish(PentestEvent.PhaseTransitioned, {
                timestamp: Date.now(),
                engagementID: state.id,
                from: oldPhase,
                to: phase,
              })
              return {
                title: `Phase: ${phase}`,
                metadata: { old_phase: oldPhase, new_phase: phase },
                output: `Phase changed: ${oldPhase} -> ${phase}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "set_mode": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const mode = d.mode as EngagementSchema.PentestMode
              if (!mode) {
                return { title: "Error", metadata: {}, output: "Error: data.mode is required for set_mode." }
              }
              const oldMode = state.mode
              yield* store.setMode(mode)
              const updated = yield* store.get()

              return {
                title: `Mode: ${mode}`,
                metadata: { old_mode: oldMode, new_mode: mode },
                output: `Mode changed: ${oldMode} -> ${mode}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_scope": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const warnings: string[] = []
              const scopeUpdate: Partial<{ -readonly [K in keyof EngagementSchema.Scope]: EngagementSchema.Scope[K] }> = {}
              if (d.targets) {
                warnings.push("Cannot modify canonical scope targets. Use discovered_targets for agent-found assets, or add_discovered_target for individual entries.")
              }
              if (d.excludes) scopeUpdate.excludes = d.excludes as string[]
              if (d.discovered_targets) scopeUpdate.discovered_targets = d.discovered_targets as string[]
              if (d.notes !== undefined) scopeUpdate.notes = d.notes as string
              yield* store.updateScope(scopeUpdate)
              const updated = yield* store.get()

              const scope = updated?.scope ?? state.scope
              yield* events.publish(PentestEvent.ScopeUpdated, {
                timestamp: Date.now(),
                engagementID: state.id,
                targets: scope.targets,
                excludes: scope.excludes,
              })
              const disc = scope.discovered_targets?.length ? `\nDiscovered: ${scope.discovered_targets.join(", ")}` : ""
              const warn = warnings.length ? `\n⚠ ${warnings.join("\n⚠ ")}` : ""
              return {
                title: "Scope updated",
                metadata: {},
                output: `Scope updated. Targets: ${scope.targets.join(", ") || "(none)"}. Excludes: ${scope.excludes.join(", ") || "(none)"}${disc}${scope.notes ? `. Notes: ${scope.notes}` : ""}${warn}`,
              }
            }

            case "add_discovered_target": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const target = d.target as string
              if (!target) {
                return { title: "Error", metadata: {}, output: "Error: data.target is required for add_discovered_target." }
              }
              const existing = state.scope.discovered_targets ?? []
              if (existing.includes(target)) {
                return { title: "Already known", metadata: {}, output: `Target "${target}" already in discovered_targets.` }
              }
              yield* store.updateScope({ discovered_targets: [...existing, target] })
              return {
                title: `Discovered: ${target}`,
                metadata: { target },
                output: `Added "${target}" to discovered targets. Total discovered: ${existing.length + 1}.`,
              }
            }

            case "add_flag": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const flag = d.flag as string
              if (!flag) {
                return { title: "Error", metadata: {}, output: "Error: data.flag is required for add_flag." }
              }
              const updated = { ...state, flags: [...state.flags, flag] }
              yield* store.save(updated)
              yield* events.publish(PentestEvent.FlagCaptured, {
                timestamp: Date.now(),
                engagementID: state.id,
                flag,
                totalCount: updated.flags.length,
              })
              return {
                title: `Flag captured`,
                metadata: { flag, count: updated.flags.length },
                output: `Flag captured (#${updated.flags.length}): ${flag}\n${countsLine(updated)}`,
              }
            }

            case "add_note": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const note = d.note as string
              if (!note) {
                return { title: "Error", metadata: {}, output: "Error: data.note is required for add_note." }
              }
              const updated = { ...state, notes: [...state.notes, note] }
              yield* store.save(updated)
              return {
                title: "Note added",
                metadata: { count: updated.notes.length },
                output: `Note added (#${updated.notes.length}): ${note}`,
              }
            }

            case "add_attack_step": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const source = d.source as string
              const target = d.target as string
              const technique = d.technique as string
              const result = d.result as string
              if (!source || !target || !technique || !result) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.source, data.target, data.technique, and data.result are required for add_attack_step.",
                }
              }
              const step = {
                timestamp: new Date().toISOString(),
                source,
                target,
                technique,
                result,
                success: d.success !== undefined ? Boolean(d.success) : true,
                mitre_attack_id: d.mitre_attack_id as string | undefined,
              } as EngagementSchema.AttackStep
              const updated = { ...state, attack_path: [...state.attack_path, step] }
              yield* store.save(updated)
              yield* events.publish(PentestEvent.AttackStepRecorded, {
                timestamp: Date.now(),
                engagementID: state.id,
                source,
                target,
                technique,
                success: step.success ?? true,
              })
              return {
                title: `Attack: ${technique}`,
                metadata: { source, target, technique, success: step.success },
                output: `Attack step recorded: ${source} -> ${target} via ${technique} (${step.success ? "SUCCESS" : "FAILED"}): ${result}${step.mitre_attack_id ? ` [${step.mitre_attack_id}]` : ""}\n${countsLine(updated)}`,
              }
            }

            case "set_domain": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const domainName = d.domain_name as string
              if (!domainName) {
                return { title: "Error", metadata: {}, output: "Error: data.domain_name is required for set_domain." }
              }
              const domain: EngagementSchema.DomainState = {
                domain_name: domainName,
                forest: d.forest as string | undefined,
                domain_sid: d.domain_sid as string | undefined,
                domain_controllers: d.domain_controllers as string[] | undefined,
                domain_admins: d.domain_admins as string[] | undefined,
                gpo_names: d.gpo_names as string[] | undefined,
                trusts: d.trusts as EngagementSchema.Trust[] | undefined,
                password_policy: d.password_policy as EngagementSchema.DomainState["password_policy"],
              }
              yield* store.setDomain(domain)
              const updated = yield* store.get()

              return {
                title: `Domain: ${domainName}`,
                metadata: { domain: domainName },
                output: `Domain set: ${domainName}${domain.forest ? ` forest:${domain.forest}` : ""}${domain.domain_controllers?.length ? ` DCs:${domain.domain_controllers.join(",")}` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_domain": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              if (!state.domain) {
                return { title: "Error", metadata: {}, output: "No domain set. Use set_domain first." }
              }
              const patch: Record<string, unknown> = {}
              for (const key of ["domain_name", "forest", "domain_sid", "domain_controllers", "domain_admins", "gpo_names", "trusts", "password_policy"]) {
                if (d[key] !== undefined) patch[key] = d[key]
              }
              yield* store.updateDomain(patch)
              const updated = yield* store.get()

              const changedFields = Object.keys(patch).join(", ")
              return {
                title: `Domain updated`,
                metadata: { changed: changedFields },
                output: `Domain "${state.domain.domain_name}" updated (${changedFields}).${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_objective": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              const title = d.title as string
              if (!id || !title) {
                return { title: "Error", metadata: {}, output: "Error: data.id and data.title are required for add_objective." }
              }
              const objective: EngagementSchema.Objective = {
                id,
                title,
                description: d.description as string | undefined,
                status: (d.status as EngagementSchema.ObjectiveStatus) || "not_started",
                priority: d.priority as EngagementSchema.ObjectivePriority | undefined,
                category: d.category as EngagementSchema.ObjectiveCategory | undefined,
                target_hosts: d.target_hosts as string[] | undefined,
                linked_vulns: d.linked_vulns as string[] | undefined,
                linked_creds: d.linked_creds as string[] | undefined,
                flags: d.flags as string[] | undefined,
                evidence: d.evidence as string | undefined,
                notes: d.notes as string | undefined,
              }
              yield* store.addObjective(objective)
              const updated = yield* store.get()

              yield* events.publish(PentestEvent.ObjectiveAdded, {
                timestamp: Date.now(),
                engagementID: state.id,
                objectiveId: id,
                title,
                priority: objective.priority,
                category: objective.category,
              })
              return {
                title: `Objective: ${title}`,
                metadata: { id, priority: objective.priority },
                output: `Objective added: [${id}] "${title}" (${objective.status})${objective.priority ? ` priority:${objective.priority}` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_objective": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for update_objective." }
              }
              const objectives = state.objectives ?? {}
              if (!objectives[id]) {
                const available = Object.keys(objectives)
                return {
                  title: "Error",
                  metadata: {},
                  output: `Objective "${id}" not found.${available.length > 0 ? ` Known: ${available.join(", ")}` : " No objectives defined."}`,
                }
              }
              const patch: Record<string, unknown> = {}
              if (d.title !== undefined) patch.title = d.title
              if (d.description !== undefined) patch.description = d.description
              if (d.status !== undefined) patch.status = d.status
              if (d.priority !== undefined) patch.priority = d.priority
              if (d.category !== undefined) patch.category = d.category
              if (d.target_hosts !== undefined) patch.target_hosts = d.target_hosts
              if (d.linked_vulns !== undefined) patch.linked_vulns = d.linked_vulns
              if (d.linked_creds !== undefined) patch.linked_creds = d.linked_creds
              if (d.flags !== undefined) patch.flags = d.flags
              if (d.evidence !== undefined) patch.evidence = d.evidence
              if (d.notes !== undefined) patch.notes = d.notes
              yield* store.updateObjective(id, patch)
              const updated = yield* store.get()

              const changedFields = Object.keys(patch).join(", ")
              yield* events.publish(PentestEvent.ObjectiveUpdated, {
                timestamp: Date.now(),
                engagementID: state.id,
                objectiveId: id,
                field: changedFields,
                newValue: JSON.stringify(patch),
              })
              return {
                title: `Objective updated: ${id}`,
                metadata: { id, changed: changedFields },
                output: `Objective "${id}" updated (${changedFields}).${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "complete_objective": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for complete_objective." }
              }
              const objectives = state.objectives ?? {}
              if (!objectives[id]) {
                return { title: "Error", metadata: {}, output: `Objective "${id}" not found.` }
              }
              const evidence = d.evidence as string | undefined
              yield* store.completeObjective(id, evidence)
              const updated = yield* store.get()

              const obj = objectives[id]!
              const completedCount = Object.values(updated?.objectives ?? {}).filter((o) => o.status === "completed").length
              const totalCount = Object.keys(updated?.objectives ?? {}).length
              yield* events.publish(PentestEvent.ObjectiveCompleted, {
                timestamp: Date.now(),
                engagementID: state.id,
                objectiveId: id,
                title: obj.title,
              })
              return {
                title: `Objective completed: ${obj.title}`,
                metadata: { id, completed: completedCount, total: totalCount },
                output: `Objective "${obj.title}" [${id}] COMPLETED.${evidence ? ` Evidence: ${evidence}` : ""}\nProgress: ${completedCount}/${totalCount} objectives.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_relationship": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const sourceType = d.source_type as string
              const sourceId = d.source_id as string
              const relType = d.rel_type as string
              const targetType = d.target_type as string
              const targetId = d.target_id as string
              if (!sourceType || !sourceId || !relType || !targetType || !targetId) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.source_type, data.source_id, data.rel_type, data.target_type, and data.target_id are required for add_relationship.",
                }
              }
              const rel = {
                source_type: sourceType,
                source_id: sourceId,
                rel_type: relType,
                target_type: targetType,
                target_id: targetId,
                metadata: d.metadata as string | undefined,
              } as EngagementSchema.Relationship
              const added = yield* store.addRelationship(rel)
              if (!added) {
                return {
                  title: "Relationship exists",
                  metadata: {},
                  output: `Relationship already exists: ${sourceType}:${sourceId} --[${relType}]--> ${targetType}:${targetId}`,
                }
              }
              const updated = yield* store.get()

              return {
                title: `Rel: ${relType}`,
                metadata: { source: sourceId, target: targetId, rel_type: relType },
                output: `Relationship added: ${sourceType}:${sourceId} --[${relType}]--> ${targetType}:${targetId}${d.metadata ? ` (${d.metadata})` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_relationship": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const sourceId = d.source_id as string
              const relType = d.rel_type as string
              const targetId = d.target_id as string
              if (!sourceId || !relType || !targetId) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.source_id, data.rel_type, and data.target_id are required for delete_relationship.",
                }
              }
              const deleted = yield* store.deleteRelationship(sourceId, relType, targetId)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Relationship not found: ${sourceId} --[${relType}]--> ${targetId}` }
              }
              const updated = yield* store.get()

              return {
                title: `Rel deleted`,
                metadata: { source: sourceId, target: targetId },
                output: `Relationship deleted: ${sourceId} --[${relType}]--> ${targetId}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            // --- Decision Memory ---
            case "add_decision": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const decision = d.decision as string
              const reasoning = d.reasoning as string
              if (!decision || !reasoning) {
                return { title: "Error", metadata: {}, output: "Error: data.decision and data.reasoning are required for add_decision." }
              }
              const entry = {
                id: d.id as string || `dec-${Date.now()}`,
                timestamp: new Date().toISOString(),
                phase: (d.phase as EngagementSchema.PentestPhase) || state.current_phase,
                decision,
                reasoning,
                alternatives: d.alternatives as string[] | undefined,
                outcome: (d.outcome as EngagementSchema.DecisionOutcome | undefined) ?? ("pending" as EngagementSchema.DecisionOutcome),
                outcome_notes: d.outcome_notes as string | undefined,
              }
              yield* store.addDecision(entry)
              return {
                title: `Decision: ${decision.slice(0, 50)}`,
                metadata: { id: entry.id, phase: entry.phase },
                output: `Decision recorded [${entry.id}]: ${decision}\nReasoning: ${reasoning}${entry.alternatives?.length ? `\nAlternatives: ${entry.alternatives.join(", ")}` : ""}`,
              }
            }

            case "update_decision_outcome": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              const outcome = d.outcome as string
              if (!id || !outcome) {
                return { title: "Error", metadata: {}, output: "Error: data.id and data.outcome (pending|successful|failed|abandoned|superseded) are required." }
              }
              const ok = yield* store.updateDecisionOutcome(id, outcome, d.notes as string | undefined)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Decision "${id}" not found.` }
              }
              return {
                title: `Decision outcome: ${id}`,
                metadata: { id, outcome },
                output: `Decision "${id}" outcome set to ${outcome}.${d.notes ? ` Notes: ${d.notes}` : ""}`,
              }
            }

            // --- Goal ---
            case "set_goal": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const text = d.text as string
              if (!text) {
                return { title: "Error", metadata: {}, output: "Error: data.text is required for set_goal." }
              }
              yield* store.setGoal(text)
              return {
                title: `Goal set`,
                metadata: { goal: text },
                output: `Goal set: "${text}". All actions should now serve this goal.`,
              }
            }

            case "update_goal": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              if (!state.goal) {
                return { title: "Error", metadata: {}, output: "No goal is set. Use set_goal first." }
              }
              const patch: { status?: EngagementSchema.GoalStatus; evidence?: string } = {}
              if (d.status) patch.status = d.status as EngagementSchema.GoalStatus
              if (d.evidence !== undefined) patch.evidence = d.evidence as string
              yield* store.updateGoal(patch)
              const updated = yield* store.get()
              return {
                title: `Goal ${patch.status ?? "updated"}`,
                metadata: { status: patch.status },
                output: `Goal "${state.goal.text}" → ${updated?.goal?.status ?? patch.status ?? state.goal.status}${patch.evidence ? `\nEvidence: ${patch.evidence}` : ""}`,
              }
            }

            case "clear_goal": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              yield* store.clearGoal()
              return {
                title: "Goal cleared",
                metadata: {},
                output: "Goal cleared. No active goal.",
              }
            }

            // --- Resolved Vectors ---
            case "record_vector": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const target = d.target as string
              const vector = d.vector as string
              const status = d.status as string
              if (!target || !vector || !status) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.target (host:port/URL), data.vector (technique), and data.status (attempted|confirmed|resolved|blocked) are required for record_vector.",
                }
              }
              // Optional in-vector sub-attempt: log the specific technique tried
              // (gadget chain, encoding, payload variant) so a re-spawn / post-compaction
              // turn does not re-explore the same dead ends within a hard grind.
              const attemptRaw = d.attempt as Record<string, unknown> | undefined
              const attempt_log = attemptRaw?.technique
                ? [
                    {
                      technique: attemptRaw.technique as string,
                      outcome: (["failed", "partial", "success"].includes(attemptRaw.outcome as string)
                        ? attemptRaw.outcome
                        : "failed") as EngagementSchema.VectorAttempt["outcome"],
                      detail: attemptRaw.detail as string | undefined,
                      timestamp: new Date().toISOString(),
                    },
                  ]
                : undefined
              const rec = {
                id: (d.id as string) || `vec-${Date.now()}`,
                timestamp: new Date().toISOString(),
                target,
                vector,
                status: status as EngagementSchema.VectorStatus,
                tested_by: d.tested_by as string | undefined,
                attempts: d.attempts as number | undefined,
                evidence: d.evidence as string | undefined,
                revisit_when: d.revisit_when as string | undefined,
                attempt_log,
              }
              const { created } = yield* store.addResolvedVector(rec)
              const updated = yield* store.get()

              const attemptNote = attempt_log ? ` | logged attempt: ${attempt_log[0]!.technique} (${attempt_log[0]!.outcome})` : ""
              return {
                title: `Vector: ${status}`,
                metadata: { target, status, created },
                output: `Vector ${created ? "recorded" : "updated (re-probe)"} [${status.toUpperCase()}]: ${target} :: ${vector}${status === "resolved" || status === "confirmed" ? " — will not be re-tested" : ""}${attemptNote}`,
              }
            }

            case "add_alert": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const title = d.title as string
              const severity = d.severity as string
              if (!title || !severity) {
                return { title: "Error", metadata: {}, output: "Error: data.title and data.severity (critical|high|medium|low|info) are required." }
              }
              const alert = {
                id: d.id as string || `alert-${Date.now()}`,
                timestamp: new Date().toISOString(),
                severity: severity as EngagementSchema.AlertSeverity,
                priority: d.priority as EngagementSchema.AlertPriority | undefined,
                source_agent: d.source_agent as string | undefined,
                title,
                details: d.details as string | undefined,
                host_ip: d.host_ip as string | undefined,
                acknowledged: false,
                ttl_minutes: d.ttl_minutes as number | undefined,
              }
              yield* store.addAlert(alert)
              const updated = yield* store.get()

              return {
                title: `Alert: ${title}`,
                metadata: { id: alert.id, severity },
                output: `Alert raised [${severity.toUpperCase()}]: ${title}${d.host_ip ? ` host:${d.host_ip}` : ""}${d.source_agent ? ` from:${d.source_agent}` : ""}`,
              }
            }

            case "acknowledge_alert": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for acknowledge_alert." }
              }
              const ok = yield* store.acknowledgeAlert(id)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Alert "${id}" not found.` }
              }
              const updated = yield* store.get()

              return {
                title: `Alert acked: ${id}`,
                metadata: { id },
                output: `Alert "${id}" acknowledged.`,
              }
            }

            // --- Live Sessions ---
            case "record_artifact": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const name = d.name as string
              const path = d.path as string
              if (!name || !path) {
                return { title: "Error", metadata: {}, output: "Error: data.name and data.path required. Record a reusable weapon/loot/script (path + how to invoke it) so other agents INVOKE it instead of re-deriving the payload." }
              }
              const ARTIFACT_TYPES = ["exploit", "loot", "script", "payload", "wordlist", "other"]
              const artType = ARTIFACT_TYPES.includes(d.type as string) ? (d.type as string) : "other"
              const artifact = {
                id: (d.id as string) || `art-${Date.now()}`,
                name,
                path,
                type: artType as EngagementSchema.ArtifactType,
                description: d.description as string | undefined,
                host_ip: d.host_ip as string | undefined,
                created_at: new Date().toISOString(),
              }
              yield* store.addArtifact(artifact)
              const updated = yield* store.get()

              return {
                title: `Artifact: ${name}`,
                metadata: { id: artifact.id, type: artType, path },
                output: `Artifact recorded [${artifact.id}]: ${artType} '${name}' @ ${path}${d.description ? ` — ${d.description}` : ""}. Reuse it (invoke, don't re-derive).`,
              }
            }

            case "add_live_session": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const rawType = d.session_type as string
              const hostIp = d.host_ip as string
              if (!rawType || !hostIp) {
                return { title: "Error", metadata: {}, output: "Error: data.session_type (shell|listener|tunnel|socks_proxy|port_forward) and data.host_ip are required." }
              }
              // Normalize common aliases → schema enum (SessionType in schema.ts), then
              // validate at add-time. Prevents an invalid value corrupting state and
              // throwing at save (e.g. the model naturally writes "proxy" for socks_proxy).
              const SESSION_ALIASES: Record<string, string> = {
                proxy: "socks_proxy", socks: "socks_proxy", socks5: "socks_proxy", socks5_proxy: "socks_proxy",
                meterpreter: "shell", reverse_shell: "shell", revshell: "shell", webshell: "shell", rce: "shell",
                forward: "port_forward", portfwd: "port_forward", "port-forward": "port_forward",
              }
              const VALID_SESSION_TYPES = ["shell", "listener", "tunnel", "socks_proxy", "port_forward"]
              const sessionType = SESSION_ALIASES[rawType.toLowerCase()] ?? rawType.toLowerCase()
              if (!VALID_SESSION_TYPES.includes(sessionType)) {
                return { title: "Error", metadata: {}, output: `Error: session_type '${rawType}' is invalid. Use one of: ${VALID_SESSION_TYPES.join("|")} (aliases accepted: proxy→socks_proxy, meterpreter/webshell/rce→shell, portfwd→port_forward).` }
              }
              const session = {
                id: d.id as string || `sess-${Date.now()}`,
                session_type: sessionType as EngagementSchema.SessionType,
                host_ip: hostIp,
                port: d.port as number | undefined,
                username: d.username as string | undefined,
                pid: d.pid as number | undefined,
                established_at: new Date().toISOString(),
                last_seen: new Date().toISOString(),
                alive: true,
                details: d.details as string | undefined,
                local_port: d.local_port as number | undefined,
                remote_target: d.remote_target as string | undefined,
              }
              yield* store.addLiveSession(session)
              const updated = yield* store.get()

              return {
                title: `Session: ${sessionType} on ${hostIp}`,
                metadata: { id: session.id, type: sessionType, host: hostIp },
                output: `Live session added [${session.id}]: ${sessionType} on ${hostIp}${d.port ? `:${d.port}` : ""} as ${d.username ?? "?"}`,
              }
            }

            case "update_live_session": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for update_live_session." }
              }
              const patch: Record<string, unknown> = {}
              for (const key of ["alive", "last_seen", "details", "pid", "local_port", "remote_target"]) {
                if (d[key] !== undefined) patch[key] = d[key]
              }
              const ok = yield* store.updateLiveSession(id, patch)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Live session "${id}" not found.` }
              }
              const updated = yield* store.get()

              return {
                title: `Session updated: ${id}`,
                metadata: { id },
                output: `Live session "${id}" updated (${Object.keys(patch).join(", ")}).`,
              }
            }

            case "remove_live_session": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for remove_live_session." }
              }
              const ok = yield* store.removeLiveSession(id)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Live session "${id}" not found.` }
              }
              const updated = yield* store.get()

              return {
                title: `Session removed: ${id}`,
                metadata: { id },
                output: `Live session "${id}" removed.`,
              }
            }

            // --- Network Segments ---
            case "add_network_segment": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const cidr = d.cidr as string
              if (!cidr) {
                return { title: "Error", metadata: {}, output: "Error: data.cidr is required for add_network_segment." }
              }
              const segment = {
                id: d.id as string || `seg-${Date.now()}`,
                name: d.name as string | undefined,
                cidr,
                vlan: d.vlan as number | undefined,
                gateway: d.gateway as string | undefined,
                reachable_from: d.reachable_from as string[] | undefined,
                pivot_host: d.pivot_host as string | undefined,
                notes: d.notes as string | undefined,
              }
              yield* store.addNetworkSegment(segment)
              const updated = yield* store.get()

              return {
                title: `Segment: ${cidr}`,
                metadata: { id: segment.id, cidr },
                output: `Network segment added [${segment.id}]: ${cidr}${d.vlan !== undefined ? ` VLAN:${d.vlan}` : ""}${d.pivot_host ? ` via pivot:${d.pivot_host}` : ""}${d.name ? ` (${d.name})` : ""}`,
              }
            }

            case "update_network_segment": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for update_network_segment." }
              }
              const patch: Record<string, unknown> = {}
              for (const key of ["name", "cidr", "vlan", "gateway", "reachable_from", "pivot_host", "notes"]) {
                if (d[key] !== undefined) patch[key] = d[key]
              }
              const ok = yield* store.updateNetworkSegment(id, patch)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Network segment "${id}" not found.` }
              }
              const updated = yield* store.get()

              return {
                title: `Segment updated: ${id}`,
                metadata: { id },
                output: `Network segment "${id}" updated (${Object.keys(patch).join(", ")}).`,
              }
            }

            case "remove_network_segment": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for remove_network_segment." }
              }
              const ok = yield* store.removeNetworkSegment(id)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Network segment "${id}" not found.` }
              }
              const updated = yield* store.get()

              return {
                title: `Segment removed: ${id}`,
                metadata: { id },
                output: `Network segment "${id}" removed.`,
              }
            }

            case "record_wordlist": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const port = d.port as number
              const toolType = d.tool_type as string
              const wordlistPath = d.wordlist_path as string
              if (!hostIp || port === undefined || !toolType || !wordlistPath) {
                return { title: "Error", metadata: {}, output: "Error: host_ip, port, tool_type, wordlist_path are all required for record_wordlist." }
              }
              const usage: EngagementSchema.WordlistUsage = {
                host_ip: hostIp,
                port,
                tool_type: toolType as EngagementSchema.WordlistToolType,
                wordlist_path: wordlistPath,
                timestamp: new Date().toISOString(),
                ...(d.results_count !== undefined ? { results_count: d.results_count as number } : {}),
                ...(d.agent_type ? { agent_type: d.agent_type as string } : {}),
              }
              const added = yield* store.addWordlistUsage(usage)
              const updated = yield* store.get()

              return {
                title: added ? `Wordlist: ${wordlistPath}` : "Wordlist (duplicate)",
                metadata: { host_ip: hostIp, port, tool_type: toolType },
                output: added
                  ? `Recorded wordlist ${wordlistPath} on ${hostIp}:${port} (${toolType})`
                  : `Wordlist already recorded for ${hostIp}:${port} (${toolType}): ${wordlistPath}`,
              }
            }

            case "set_pause": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const pause = (d.pause ?? d.behavior) as string
              if (!pause || !["never", "always", "checkpoint"].includes(pause)) {
                return { title: "Error", metadata: {}, output: "Error: data.pause must be one of: never, always, checkpoint" }
              }
              yield* store.setPauseBehavior(pause as EngagementSchema.PauseBehavior)
              const updated = yield* store.get()

              return {
                title: `Pause: ${pause}`,
                metadata: { pause },
                output: `Pause on finding set to: ${pause}`,
              }
            }

            default: {
              return { title: "Error", metadata: {}, output: `Unknown action: ${params.action}` }
            }
          }
        }).pipe(Effect.orDie)

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (params.action === "batch") {
            const raw = params.data ?? {}
            const d = (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, any>
            const ops = d.operations as Array<{ action: string; data: unknown }> | undefined
            if (!Array.isArray(ops) || ops.length === 0) {
              return {
                title: "Error",
                metadata: {},
                output: "Error: data.operations must be a non-empty array of {action, data} objects.",
              }
            }
            if (ops.length > 100) {
              return {
                title: "Error",
                metadata: {},
                output: "Error: batch limited to 100 operations. Split into multiple batches.",
              }
            }
            const results: string[] = []
            let succeeded = 0
            let failed = 0
            for (const op of ops) {
              if (!op.action || typeof op.action !== "string") {
                results.push(`[FAIL] missing action`)
                failed++
                continue
              }
              try {
                const subResult = yield* executeAction({ action: op.action, data: op.data }, _ctx)
                if (subResult.title === "Error") {
                  results.push(`[FAIL] ${op.action}: ${subResult.output}`)
                  failed++
                } else {
                  results.push(`[OK] ${op.action}: ${subResult.title}`)
                  succeeded++
                }
              } catch (err: unknown) {
                results.push(`[FAIL] ${op.action}: ${String(err)}`)
                failed++
              }
            }
            const updated = yield* store.get()
            return {
              title: `Batch: ${succeeded}/${ops.length} succeeded`,
              metadata: { succeeded, failed, total: ops.length },
              output: `Batch: ${succeeded} succeeded, ${failed} failed out of ${ops.length} operations.\n${results.join("\n")}${updated ? `\n${countsLine(updated)}` : ""}`,
            }
          }
          return yield* executeAction(params, _ctx)
        }).pipe(Effect.orDie),
    }
  }),
)
