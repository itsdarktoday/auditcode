import { Effect, Schema } from "effect"
import { EngagementStore } from "@auditcode/core/engagement/store"
import { EngagementSchema } from "@auditcode/core/engagement/schema"
import DESCRIPTION from "./attack-path-suggest.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  from_host: Schema.optional(Schema.String).annotate({
    description: "Starting host IP (defaults to first compromised host)",
  }),
  to_host: Schema.optional(Schema.String).annotate({
    description: "Destination host IP (finds optimal paths if specified)",
  }),
  objective: Schema.optional(Schema.String).annotate({
    description: 'What to reach: "domain controller", "10.10.10.0/24 subnet", etc.',
  }),
})

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GraphNode {
  ip: string
  compromised: boolean
  serviceCount: number
  isDC: boolean
  hasAccess: boolean
  accessUsers: string[]
}

interface WeightedEdge {
  from: string
  to: string
  relType: string
  cost: number
  metadata?: string
  credentialId?: string
  vulnId?: string
  opsecLevel: "silent" | "quiet" | "noisy"
}

interface WeightedPath {
  nodes: string[]
  edges: WeightedEdge[]
  totalCost: number
  difficulty: string
}

// ---------------------------------------------------------------------------
// Edge cost model
// ---------------------------------------------------------------------------

const EDGE_BASE_COSTS: Record<string, number> = {
  MEMBER_OF: 5,
  LATERAL_MOVE: 10,
  ADMIN_OF: 15,
  AUTHENTICATES_TO: 20,
  CONTROLS: 20,
  CREDENTIAL_FROM: 25,
  PIVOT_TO: 30,
  EXPLOITED_VIA: 35,
  REACHABLE_FROM: 40,
  TRUSTS: 50,
}

const DEFAULT_EDGE_COST = 35
const SYNTHETIC_EDGE_COST = 80

// ---------------------------------------------------------------------------
// MinHeap
// ---------------------------------------------------------------------------

class MinHeap<T> {
  private heap: { priority: number; value: T }[] = []

  push(priority: number, value: T): void {
    this.heap.push({ priority, value })
    this._bubbleUp(this.heap.length - 1)
  }

  pop(): T | undefined {
    if (this.heap.length === 0) return undefined
    const top = this.heap[0]!
    const last = this.heap.pop()!
    if (this.heap.length > 0) {
      this.heap[0] = last
      this._sinkDown(0)
    }
    return top.value
  }

  isEmpty(): boolean {
    return this.heap.length === 0
  }

  private _bubbleUp(idx: number): void {
    while (idx > 0) {
      const parent = (idx - 1) >> 1
      if (this.heap[parent]!.priority <= this.heap[idx]!.priority) break
      ;[this.heap[parent], this.heap[idx]] = [this.heap[idx]!, this.heap[parent]!]
      idx = parent
    }
  }

  private _sinkDown(idx: number): void {
    const len = this.heap.length
    while (true) {
      let smallest = idx
      const left = 2 * idx + 1
      const right = 2 * idx + 2
      if (left < len && this.heap[left]!.priority < this.heap[smallest]!.priority) smallest = left
      if (right < len && this.heap[right]!.priority < this.heap[smallest]!.priority) smallest = right
      if (smallest === idx) break
      ;[this.heap[smallest], this.heap[idx]] = [this.heap[idx]!, this.heap[smallest]!]
      idx = smallest
    }
  }
}

// ---------------------------------------------------------------------------
// Cost computation
// ---------------------------------------------------------------------------

function computeEdgeCost(
  state: EngagementSchema.State,
  rel: EngagementSchema.Relationship,
  srcIp: string,
  dstIp: string,
): { cost: number; opsecLevel: "silent" | "quiet" | "noisy"; credentialId?: string; vulnId?: string } {
  const baseCost = EDGE_BASE_COSTS[rel.rel_type] ?? DEFAULT_EDGE_COST

  // --- credential confidence factor ---
  let credFactor = 1.0
  let credentialId: string | undefined
  // Find credential linking src to dst (any access on src that has a credential)
  const srcHost = state.hosts[srcIp]
  if (srcHost) {
    for (const acc of srcHost.access) {
      if (acc.credential_id) {
        const cred = state.credentials[acc.credential_id]
        if (cred) {
          credFactor = 1.1 - (cred.confidence ?? 0.5)
          credentialId = acc.credential_id
          break
        }
      }
    }
  }
  // Also check if the relationship metadata references a credential
  if (!credentialId && rel.metadata) {
    const credMatch = rel.metadata.match(/cred(?:ential)?[_:](\S+)/i)
    if (credMatch?.[1]) {
      const cred = state.credentials[credMatch[1]]
      if (cred) {
        credFactor = 1.1 - (cred.confidence ?? 0.5)
        credentialId = credMatch[1]
      }
    }
  }

  // --- vuln confidence factor (for EXPLOITED_VIA) ---
  let vulnFactor = 1.0
  let vulnId: string | undefined
  if (rel.rel_type === "EXPLOITED_VIA") {
    const dstHost = state.hosts[dstIp]
    if (dstHost) {
      // Find the vuln matching this exploit relationship
      for (const v of dstHost.vulns) {
        if (v.id && (rel.target_id === v.id || rel.metadata?.includes(v.id))) {
          vulnFactor = 1.1 - (v.confidence ?? 0.5)
          vulnId = v.id
          break
        }
      }
      // Fallback: use highest-confidence vuln on the target
      if (!vulnId && dstHost.vulns.length > 0) {
        const best = [...dstHost.vulns].sort((a, b) => (b.confidence ?? 0.5) - (a.confidence ?? 0.5))[0]!
        vulnFactor = 1.1 - (best.confidence ?? 0.5)
        vulnId = best.id
      }
    }
  }

  // --- temporal penalty (expired/expiring tickets) ---
  let temporalPenalty = 0
  if (credentialId) {
    const cred = state.credentials[credentialId]
    if (cred?.ticket_expiry) {
      const expiryTime = new Date(cred.ticket_expiry).getTime()
      const now = Date.now()
      if (expiryTime <= now) {
        return { cost: Infinity, opsecLevel: "noisy", credentialId, vulnId }
      }
      const minutesLeft = (expiryTime - now) / (1000 * 60)
      if (minutesLeft <= 30) {
        temporalPenalty = 50
      }
    }
  }

  // --- live session bonus ---
  let sessionFactor = 1.0
  const sessions = state.live_sessions ?? []
  const hasActiveSession = sessions.some(
    (s) => s.host_ip === srcIp && s.alive !== false,
  )
  if (hasActiveSession) {
    sessionFactor = 0.7
  }

  // --- OPSEC penalty ---
  let opsecPenalty = 0
  let opsecLevel: "silent" | "quiet" | "noisy" = "quiet"
  if (rel.rel_type === "EXPLOITED_VIA") {
    opsecPenalty = 20
    opsecLevel = "noisy"
  } else if (rel.rel_type === "REACHABLE_FROM" && !credentialId) {
    // Blind reachability without credentials — noisy probing likely
    opsecPenalty = 10
    opsecLevel = "noisy"
  } else if (
    rel.rel_type === "MEMBER_OF" ||
    rel.rel_type === "ADMIN_OF" ||
    rel.rel_type === "CONTROLS"
  ) {
    opsecLevel = "silent"
  }

  const rawCost = baseCost * credFactor * vulnFactor * sessionFactor + opsecPenalty + temporalPenalty
  return {
    cost: Math.max(1, rawCost),
    opsecLevel,
    credentialId,
    vulnId,
  }
}

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

function buildWeightedGraph(state: EngagementSchema.State): Map<string, WeightedEdge[]> {
  const adj = new Map<string, WeightedEdge[]>()
  const hostIPs = new Set(Object.keys(state.hosts))

  const addEdge = (edge: WeightedEdge) => {
    if (!adj.has(edge.from)) adj.set(edge.from, [])
    adj.get(edge.from)!.push(edge)
  }

  // Ensure all host IPs have entries in adjacency list
  for (const ip of hostIPs) {
    if (!adj.has(ip)) adj.set(ip, [])
  }

  const rels = state.relationships ?? []

  // --- Process ALL relationship types ---
  for (const rel of rels) {
    const srcId = rel.source_id
    const dstId = rel.target_id

    // Direct host-to-host edges
    if (rel.source_type === "host" && rel.target_type === "host") {
      if (hostIPs.has(srcId) && hostIPs.has(dstId)) {
        const { cost, opsecLevel, credentialId, vulnId } = computeEdgeCost(state, rel, srcId, dstId)
        addEdge({
          from: srcId,
          to: dstId,
          relType: rel.rel_type,
          cost,
          metadata: rel.metadata ?? undefined,
          credentialId,
          vulnId,
          opsecLevel,
        })
      }
      continue
    }

    // credential → AUTHENTICATES_TO → host: project onto host graph
    // Find which host(s) own this credential via access entries
    if (rel.source_type === "credential" && rel.target_type === "host" && hostIPs.has(dstId)) {
      const credId = srcId
      const ownerHosts = findCredentialOwnerHosts(state, credId)
      for (const ownerIp of ownerHosts) {
        if (ownerIp === dstId) continue
        const { cost, opsecLevel } = computeEdgeCost(state, rel, ownerIp, dstId)
        addEdge({
          from: ownerIp,
          to: dstId,
          relType: rel.rel_type,
          cost,
          metadata: rel.metadata ?? undefined,
          credentialId: credId,
          opsecLevel,
        })
      }
      continue
    }

    // user → ADMIN_OF → domain: edges from user's hosts to domain controllers
    if (
      (rel.source_type === "user" || rel.source_type === "group") &&
      rel.target_type === "domain" &&
      (rel.rel_type === "ADMIN_OF" || rel.rel_type === "CONTROLS" || rel.rel_type === "MEMBER_OF")
    ) {
      const userHosts = findEntityHosts(state, srcId)
      const dcHosts = findDomainControllers(state, dstId)
      for (const userHost of userHosts) {
        for (const dcHost of dcHosts) {
          if (userHost === dcHost) continue
          const { cost, opsecLevel } = computeEdgeCost(state, rel, userHost, dcHost)
          addEdge({
            from: userHost,
            to: dcHost,
            relType: rel.rel_type,
            cost: cost * 0.8, // AD relationship bonus — known path
            metadata: `${rel.source_type}:${srcId} ${rel.rel_type} domain:${dstId}`,
            opsecLevel,
          })
        }
      }
      continue
    }

    // domain → TRUSTS → domain: DC-to-DC edges
    if (rel.source_type === "domain" && rel.target_type === "domain" && rel.rel_type === "TRUSTS") {
      const srcDCs = findDomainControllers(state, srcId)
      const dstDCs = findDomainControllers(state, dstId)
      for (const srcDC of srcDCs) {
        for (const dstDC of dstDCs) {
          if (srcDC === dstDC) continue
          const { cost, opsecLevel } = computeEdgeCost(state, rel, srcDC, dstDC)
          addEdge({
            from: srcDC,
            to: dstDC,
            relType: "TRUSTS",
            cost,
            metadata: `trust: ${srcId} -> ${dstId}`,
            opsecLevel,
          })
        }
      }
      continue
    }

    // Generic fallback: if both endpoints resolve to known hosts, create edge
    if (hostIPs.has(srcId) && hostIPs.has(dstId)) {
      const { cost, opsecLevel, credentialId, vulnId } = computeEdgeCost(state, rel, srcId, dstId)
      addEdge({
        from: srcId,
        to: dstId,
        relType: rel.rel_type,
        cost,
        metadata: rel.metadata ?? undefined,
        credentialId,
        vulnId,
        opsecLevel,
      })
    }
  }

  // --- Synthetic edges ---
  const segments = state.network_segments ?? []
  const compromisedIPs = new Set(
    Object.entries(state.hosts)
      .filter(([_, h]) => h.access.length > 0)
      .map(([ip]) => ip),
  )

  if (segments.length > 0) {
    // Build segment membership: ip -> segment IDs
    const ipToSegments = new Map<string, string[]>()
    for (const seg of segments) {
      const { network, prefixLen } = parseCIDR(seg.cidr)
      if (!network) continue
      for (const ip of hostIPs) {
        if (ipInCIDR(ip, network, prefixLen)) {
          const list = ipToSegments.get(ip) ?? []
          list.push(seg.id)
          ipToSegments.set(ip, list)
        }
      }
    }

    // Add synthetic edges between compromised hosts and other hosts in the same segment
    for (const srcIp of compromisedIPs) {
      const srcSegments = ipToSegments.get(srcIp) ?? []
      for (const dstIp of hostIPs) {
        if (srcIp === dstIp) continue
        const dstSegments = ipToSegments.get(dstIp) ?? []
        const sharedSegment = srcSegments.some((s) => dstSegments.includes(s))
        if (!sharedSegment) continue

        // Only add synthetic if no explicit edge exists already
        const existing = adj.get(srcIp) ?? []
        if (existing.some((e) => e.from === srcIp && e.to === dstIp)) continue

        addEdge({
          from: srcIp,
          to: dstIp,
          relType: "SYNTHETIC",
          cost: SYNTHETIC_EDGE_COST,
          metadata: "same network segment",
          opsecLevel: "noisy",
        })
      }
    }
  }

  return adj
}

// --- Helper: find hosts that own a credential (via access entries) ---
function findCredentialOwnerHosts(state: EngagementSchema.State, credId: string): string[] {
  const hosts: string[] = []
  for (const [ip, host] of Object.entries(state.hosts)) {
    if (host.access.some((a) => a.credential_id === credId)) {
      hosts.push(ip)
    }
  }
  // If no host directly references the credential, check if any compromised host
  // has the same username as the credential
  if (hosts.length === 0) {
    const cred = state.credentials[credId]
    if (cred?.username) {
      for (const [ip, host] of Object.entries(state.hosts)) {
        if (host.access.some((a) => a.username === cred.username) && host.access.length > 0) {
          hosts.push(ip)
        }
      }
    }
  }
  return hosts
}

// --- Helper: find hosts where a user/group entity is present ---
function findEntityHosts(state: EngagementSchema.State, entityId: string): string[] {
  const hosts: string[] = []
  for (const [ip, host] of Object.entries(state.hosts)) {
    // Check if any access on this host matches the entity
    if (host.access.some((a) => a.username === entityId || a.username.toLowerCase() === entityId.toLowerCase())) {
      hosts.push(ip)
    }
  }
  return hosts
}

// --- Helper: find domain controller IPs ---
function findDomainControllers(state: EngagementSchema.State, domainId: string): string[] {
  const dcs: string[] = []

  // Check state.domain for domain controller list
  if (state.domain) {
    const domName = state.domain.domain_name?.toLowerCase()
    if (domName === domainId.toLowerCase() || domainId.toLowerCase().includes(domName ?? "")) {
      if (state.domain.domain_controllers) {
        for (const dcRef of state.domain.domain_controllers) {
          if (state.hosts[dcRef]) dcs.push(dcRef)
        }
      }
    }
  }

  // Also check host domain_info
  for (const [ip, host] of Object.entries(state.hosts)) {
    if (
      host.domain_info?.is_dc === true &&
      (host.domain_info.domain?.toLowerCase() === domainId.toLowerCase() || !host.domain_info.domain)
    ) {
      if (!dcs.includes(ip)) dcs.push(ip)
    }
  }

  return dcs
}

// ---------------------------------------------------------------------------
// CIDR utilities
// ---------------------------------------------------------------------------

function ipToUint32(ip: string): number | null {
  const parts = ip.split(".")
  if (parts.length !== 4) return null
  let result = 0
  for (const part of parts) {
    const n = parseInt(part, 10)
    if (isNaN(n) || n < 0 || n > 255) return null
    result = (result << 8) | n
  }
  return result >>> 0
}

function parseCIDR(cidr: string): { network: number | null; prefixLen: number } {
  const slash = cidr.indexOf("/")
  if (slash === -1) {
    return { network: ipToUint32(cidr), prefixLen: 32 }
  }
  const ip = cidr.substring(0, slash)
  const prefix = parseInt(cidr.substring(slash + 1), 10)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) {
    return { network: null, prefixLen: 32 }
  }
  const addr = ipToUint32(ip)
  if (addr === null) return { network: null, prefixLen: prefix }
  // Mask to network address
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  return { network: (addr & mask) >>> 0, prefixLen: prefix }
}

function ipInCIDR(ip: string, network: number, prefixLen: number): boolean {
  const addr = ipToUint32(ip)
  if (addr === null) return false
  if (prefixLen === 0) return true
  const mask = (0xffffffff << (32 - prefixLen)) >>> 0
  return ((addr & mask) >>> 0) === network
}

// ---------------------------------------------------------------------------
// Dijkstra's algorithm
// ---------------------------------------------------------------------------

function dijkstra(
  adj: Map<string, WeightedEdge[]>,
  start: string,
  end: string,
): WeightedPath | undefined {
  const dist = new Map<string, number>()
  const prev = new Map<string, { node: string; edge: WeightedEdge } | null>()
  const heap = new MinHeap<string>()

  dist.set(start, 0)
  prev.set(start, null)
  heap.push(0, start)

  while (!heap.isEmpty()) {
    const current = heap.pop()!
    const currentDist = dist.get(current)!

    if (current === end) {
      return reconstructPath(prev, start, end, currentDist)
    }

    const edges = adj.get(current) ?? []
    for (const edge of edges) {
      if (!isFinite(edge.cost)) continue
      const newDist = currentDist + edge.cost
      const known = dist.get(edge.to)
      if (known === undefined || newDist < known) {
        dist.set(edge.to, newDist)
        prev.set(edge.to, { node: current, edge })
        heap.push(newDist, edge.to)
      }
    }
  }

  return undefined
}

function reconstructPath(
  prev: Map<string, { node: string; edge: WeightedEdge } | null>,
  start: string,
  end: string,
  totalCost: number,
): WeightedPath {
  const nodes: string[] = []
  const edges: WeightedEdge[] = []
  let current: string | undefined = end

  while (current !== undefined && current !== start) {
    nodes.unshift(current)
    const entry = prev.get(current)
    if (!entry) break
    edges.unshift(entry.edge)
    current = entry.node
  }
  nodes.unshift(start)

  return {
    nodes,
    edges,
    totalCost,
    difficulty: computeDifficulty(totalCost),
  }
}

export function computeDifficulty(totalCost: number): string {
  if (totalCost <= 30) return "Easy"
  if (totalCost <= 80) return "Medium"
  if (totalCost <= 150) return "Hard"
  return "Very Hard"
}

// ---------------------------------------------------------------------------
// Yen's K-Shortest Paths
// ---------------------------------------------------------------------------

function yenKShortest(
  adj: Map<string, WeightedEdge[]>,
  start: string,
  end: string,
  k: number = 3,
): WeightedPath[] {
  const result: WeightedPath[] = []

  // Find first shortest path
  const first = dijkstra(adj, start, end)
  if (!first) return result
  result.push(first)

  // Candidates (potential k-shortest paths)
  const candidates: WeightedPath[] = []

  for (let i = 1; i < k; i++) {
    const prevPath = result[i - 1]!

    for (let j = 0; j < prevPath.nodes.length - 1; j++) {
      const spurNode = prevPath.nodes[j]!
      const rootPath = prevPath.nodes.slice(0, j + 1)
      const rootEdges = prevPath.edges.slice(0, j)
      const rootCost = rootEdges.reduce((sum, e) => sum + e.cost, 0)

      // Build modified adjacency list: remove edges that share the same root path
      const removedEdges: { from: string; to: string }[] = []
      for (const p of result) {
        if (p.nodes.length > j && arraysEqual(p.nodes.slice(0, j + 1), rootPath)) {
          if (j < p.edges.length) {
            removedEdges.push({ from: p.edges[j]!.from, to: p.edges[j]!.to })
          }
        }
      }

      // Remove root path nodes (except spur node) from graph
      const excludedNodes = new Set(rootPath.slice(0, j))

      // Create filtered adjacency
      const filteredAdj = new Map<string, WeightedEdge[]>()
      for (const [node, edges] of adj) {
        if (excludedNodes.has(node)) continue
        const filtered = edges.filter((e) => {
          if (excludedNodes.has(e.to)) return false
          if (
            e.from === spurNode &&
            removedEdges.some((r) => r.from === e.from && r.to === e.to)
          ) {
            return false
          }
          return true
        })
        filteredAdj.set(node, filtered)
      }

      // Find spur path
      const spurPath = dijkstra(filteredAdj, spurNode!, end)
      if (!spurPath) continue

      // Combine root + spur
      const totalNodes = [...rootPath.slice(0, -1), ...spurPath.nodes]
      const totalEdges = [...rootEdges, ...spurPath.edges]
      const totalCost = rootCost + spurPath.totalCost

      const candidate: WeightedPath = {
        nodes: totalNodes,
        edges: totalEdges,
        totalCost,
        difficulty: computeDifficulty(totalCost),
      }

      // Avoid duplicates
      const pathKey = totalNodes.join("->")
      const isDuplicate =
        candidates.some((c) => c.nodes.join("->") === pathKey) ||
        result.some((r) => r.nodes.join("->") === pathKey)
      if (!isDuplicate) {
        candidates.push(candidate)
      }
    }

    if (candidates.length === 0) break

    // Sort candidates by cost and pick the best
    candidates.sort((a, b) => a.totalCost - b.totalCost)
    const best = candidates.shift()!
    result.push(best)
  }

  return result
}

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// Objective resolution
// ---------------------------------------------------------------------------

function resolveObjectiveTargets(
  state: EngagementSchema.State,
  objective: string,
): string[] {
  const targets: string[] = []
  const lower = objective.toLowerCase().trim()

  // Check if it matches a stored objective's target_hosts
  if (state.objectives) {
    for (const obj of Object.values(state.objectives)) {
      if (
        obj.title.toLowerCase().includes(lower) ||
        lower.includes(obj.title.toLowerCase()) ||
        obj.id.toLowerCase() === lower
      ) {
        if (obj.target_hosts) {
          targets.push(...obj.target_hosts)
        }
      }
    }
    if (targets.length > 0) return [...new Set(targets)]
  }

  // "domain controller" / "dc" / "domain admin"
  if (lower.includes("domain controller") || lower === "dc" || lower === "dcs") {
    for (const [ip, host] of Object.entries(state.hosts)) {
      if (host.domain_info?.is_dc === true) {
        targets.push(ip)
      }
    }
    // Also check state.domain.domain_controllers
    if (state.domain?.domain_controllers) {
      for (const dc of state.domain.domain_controllers) {
        if (state.hosts[dc] && !targets.includes(dc)) {
          targets.push(dc)
        }
      }
    }
    if (targets.length > 0) return targets
  }

  // CIDR notation: e.g. "10.10.10.0/24" or "10.10.10.0/24 subnet"
  const cidrMatch = objective.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})/)
  if (cidrMatch) {
    const { network, prefixLen } = parseCIDR(cidrMatch[1]!)
    if (network !== null) {
      for (const ip of Object.keys(state.hosts)) {
        if (ipInCIDR(ip, network, prefixLen)) {
          targets.push(ip)
        }
      }
      if (targets.length > 0) return targets
    }
  }

  // Exact IP match
  const ipMatch = objective.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
  if (ipMatch && state.hosts[ipMatch[1]!]) {
    return [ipMatch[1]!]
  }

  // Keyword search in hostnames, OS, services
  for (const [ip, host] of Object.entries(state.hosts)) {
    if (host.hostname?.toLowerCase().includes(lower)) {
      targets.push(ip)
    } else if (host.os?.toLowerCase().includes(lower)) {
      targets.push(ip)
    } else if (host.services.some((s) => s.service?.toLowerCase().includes(lower))) {
      targets.push(ip)
    }
  }

  return [...new Set(targets)]
}

// ---------------------------------------------------------------------------
// Display helpers (kept from original)
// ---------------------------------------------------------------------------

function suggestTunnelType(state: EngagementSchema.State, hostIp: string): string {
  const host = state.hosts[hostIp]
  if (!host) return "chisel"
  const hasSSH = host.services.some((s) => s.service === "ssh" || s.port === 22)
  if (hasSSH) return "ssh_dynamic"
  return "chisel"
}

function findCredsDescription(state: EngagementSchema.State, hostIp: string): string {
  const host = state.hosts[hostIp]
  if (!host) return "no credentials available"
  for (const access of host.access) {
    const cred = Object.values(state.credentials).find(
      (c) => c.username === access.username && c.value,
    )
    if (cred) return `${cred.username} (${cred.cred_type ?? "password"})`
  }
  return "no credentials — enumerate/exploit first"
}

function scoreHost(
  node: GraphNode,
  objectiveTargets: string[],
): number {
  let score = 0
  if (node.isDC) score += 100
  score += node.serviceCount * 5
  if (!node.compromised) score += 10
  if (objectiveTargets.includes(node.ip)) score += 200
  return score
}

function estimateComplexity(edgeCost: number): "low" | "medium" | "high" {
  if (edgeCost < 25) return "low"
  if (edgeCost <= 50) return "medium"
  return "high"
}

// ---------------------------------------------------------------------------
// Path formatting
// ---------------------------------------------------------------------------

function formatWeightedPath(
  state: EngagementSchema.State,
  path: WeightedPath,
  idx: number,
): string {
  const lines: string[] = []
  const label = idx === 0 ? " (RECOMMENDED)" : ""
  const costStr = path.totalCost === Infinity ? "UNREACHABLE" : path.totalCost.toFixed(1)
  lines.push(`=== Path ${idx + 1}${label} — Cost: ${costStr} | Difficulty: ${path.difficulty} ===`)

  for (let i = 0; i < path.edges.length; i++) {
    const edge = path.edges[i]!
    const complexity = estimateComplexity(edge.cost)
    lines.push(`  Hop ${i + 1}: ${edge.from} -> ${edge.to} [${edge.relType}, cost: ${edge.cost.toFixed(1)}]`)

    // Credential annotation
    if (edge.credentialId) {
      const cred = state.credentials[edge.credentialId]
      if (cred) {
        const conf = cred.confidence !== undefined ? cred.confidence.toFixed(2) : "0.50"
        lines.push(`    Credentials: ${cred.username ?? "unknown"} (${cred.cred_type ?? "password"}) — confidence: ${conf}`)
      }
    } else {
      const credsDesc = findCredsDescription(state, edge.from)
      if (!credsDesc.includes("no credentials")) {
        lines.push(`    Credentials: ${credsDesc}`)
      }
    }

    // Vuln annotation
    if (edge.vulnId) {
      const dstHost = state.hosts[edge.to]
      if (dstHost) {
        const vuln = dstHost.vulns.find((v) => v.id === edge.vulnId)
        if (vuln) {
          lines.push(`    Exploit: ${vuln.title} [${(vuln.severity ?? "medium").toUpperCase()}] — confidence: ${(vuln.confidence ?? 0.5).toFixed(2)}`)
        }
      }
    }

    lines.push(`    OPSEC: ${edge.opsecLevel} | Complexity: ${complexity}`)

    // Tunnel suggestion for the hop
    const tunnel = suggestTunnelType(state, edge.from)
    lines.push(`    Tunnel: ${tunnel}`)
    lines.push("")
  }

  return lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tool definition
// ---------------------------------------------------------------------------

export const AttackPathSuggestTool = Tool.define(
  "attack_path_suggest",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) {
            return { title: "Error", metadata: {}, output: "No engagement loaded." }
          }

          const hostEntries = Object.entries(state.hosts)
          const compromised = hostEntries.filter(([_, h]) => h.access.length > 0)

          if (compromised.length === 0) {
            return {
              title: "No pivot sources",
              metadata: {},
              output: "No compromised hosts to pivot from. Gain initial access first.",
            }
          }

          const fromIp = params.from_host ?? compromised[0]![0]
          const fromHost = state.hosts[fromIp]
          if (!fromHost || fromHost.access.length === 0) {
            return {
              title: "Error",
              metadata: {},
              output: `Host ${fromIp} is not compromised or not in engagement. Cannot pivot from it.`,
            }
          }

          // Resolve objective targets for scoring
          const objectiveTargets = params.objective
            ? resolveObjectiveTargets(state, params.objective)
            : []

          // Determine effective target
          let effectiveTarget = params.to_host
          if (!effectiveTarget && objectiveTargets.length === 1) {
            effectiveTarget = objectiveTargets[0]
          }

          const adj = buildWeightedGraph(state)

          // --- Path mode: find K-shortest paths to a specific target ---
          if (effectiveTarget) {
            if (!state.hosts[effectiveTarget]) {
              return {
                title: "Error",
                metadata: {},
                output: `Target host ${effectiveTarget} not found in engagement. Add it with state_update first.`,
              }
            }

            const paths = yenKShortest(adj, fromIp, effectiveTarget, 3)

            if (paths.length === 0) {
              return {
                title: "No path found",
                metadata: { from: fromIp, to: effectiveTarget },
                output: `No path found from ${fromIp} to ${effectiveTarget}. The target may be in an unreachable network segment. Consider:\n1. Enumerate more services on intermediate hosts\n2. Add network segments with state_update\n3. Check if additional pivot hosts are needed\n4. Add relationships (REACHABLE_FROM, LATERAL_MOVE) between hosts`,
              }
            }

            const lines: string[] = [
              `Attack paths: ${fromIp} -> ${effectiveTarget} (${paths.length} route${paths.length > 1 ? "s" : ""} found)`,
              "",
            ]

            if (objectiveTargets.length > 0 && params.objective) {
              lines.push(`Objective: "${params.objective}" -> resolved to: ${objectiveTargets.join(", ")}`)
              lines.push("")
            }

            for (let i = 0; i < paths.length; i++) {
              lines.push(formatWeightedPath(state, paths[i]!, i))
            }

            // Recommendation
            const best = paths[0]!
            const bestComplexity = estimateComplexity(
              best.edges.length > 0 ? best.totalCost / best.edges.length : 0,
            )
            lines.push(
              `Recommendation: Path 1 is cheapest (${best.totalCost.toFixed(1)} total, ${bestComplexity} avg complexity). Execute with tunnel_manage for each hop.`,
            )

            return {
              title: `${paths.length} attack paths (best cost: ${best.totalCost.toFixed(1)})`,
              metadata: {
                from: fromIp,
                to: effectiveTarget,
                paths: paths.length,
                best_cost: Math.round(best.totalCost * 10) / 10,
                best_difficulty: best.difficulty,
              },
              output: lines.join("\n"),
            }
          }

          // --- Suggest mode: rank all reachable targets ---
          const nodes = new Map<string, GraphNode>()
          for (const [ip, host] of hostEntries) {
            nodes.set(ip, {
              ip,
              compromised: host.access.length > 0,
              serviceCount: host.services.length,
              isDC: host.domain_info?.is_dc === true,
              hasAccess: host.access.length > 0,
              accessUsers: host.access.map((a) => a.username),
            })
          }

          // Find best path to each non-compromised host
          interface TargetCandidate {
            ip: string
            node: GraphNode
            bestPath: WeightedPath
            hostScore: number
          }

          const candidates: TargetCandidate[] = []
          const unexplored = [...nodes.values()].filter((n) => !n.compromised)

          for (const target of unexplored) {
            const path = dijkstra(adj, fromIp, target.ip)
            if (!path || !isFinite(path.totalCost)) continue
            const hostSc = scoreHost(target, objectiveTargets)
            candidates.push({
              ip: target.ip,
              node: target,
              bestPath: path,
              hostScore: hostSc,
            })
          }

          // Sort by: objective match first, then by cost-adjusted score
          // Score formula: hostScore / (1 + totalCost/50) — balances value vs. difficulty
          candidates.sort((a, b) => {
            const aScore = a.hostScore / (1 + a.bestPath.totalCost / 50)
            const bScore = b.hostScore / (1 + b.bestPath.totalCost / 50)
            return bScore - aScore
          })

          const topN = candidates.slice(0, 10)

          // Check network segments for unreachable targets
          const segments = state.network_segments ?? []
          const compromisedIPs = new Set(compromised.map(([ip]) => ip))
          const reachableSegments = segments.filter((seg) =>
            seg.reachable_from?.some((r) => compromisedIPs.has(r)),
          )
          const unreachableSegments = segments.filter(
            (seg) => !seg.reachable_from?.some((r) => compromisedIPs.has(r)),
          )

          if (topN.length === 0 && unreachableSegments.length === 0) {
            return {
              title: "No pivot targets",
              metadata: {},
              output:
                "All discovered hosts are either compromised or unreachable from current positions. Enumerate more hosts or add network segments.",
            }
          }

          const lines: string[] = [
            `Pivot suggestions from ${fromIp} (${topN.length} targets):`,
            "",
          ]

          if (objectiveTargets.length > 0 && params.objective) {
            lines.push(`Objective: "${params.objective}" -> targets: ${objectiveTargets.join(", ")} (scored +200)`)
            lines.push("")
          }

          for (let i = 0; i < topN.length; i++) {
            const c = topN[i]!
            const path = c.bestPath
            const costStr = path.totalCost.toFixed(1)
            const avgEdgeCost = path.edges.length > 0 ? path.totalCost / path.edges.length : 0
            const complexity = estimateComplexity(avgEdgeCost)
            const isObjective = objectiveTargets.includes(c.ip)
            const reason = c.node.isDC
              ? "DOMAIN CONTROLLER — highest priority"
              : isObjective
                ? "OBJECTIVE TARGET"
                : c.node.serviceCount > 5
                  ? `${c.node.serviceCount} services — likely important server`
                  : "unexplored host"

            lines.push(`${i + 1}. ${c.ip} [${complexity.toUpperCase()}] — ${reason}`)
            lines.push(`   Path: ${path.nodes.join(" -> ")} (${path.edges.length} hops)`)
            lines.push(`   Cost: ${costStr} | Difficulty: ${path.difficulty}`)
            lines.push(`   Tunnel: ${suggestTunnelType(state, fromIp)} | Creds: ${findCredsDescription(state, fromIp)}`)

            // Show edge breakdown for top 3
            if (i < 3 && path.edges.length > 0) {
              const edgeInfo = path.edges
                .map((e) => `${e.relType}(${e.cost.toFixed(0)})`)
                .join(" -> ")
              lines.push(`   Edges: ${edgeInfo}`)
            }
            lines.push("")
          }

          if (segments.length === 0) {
            lines.push("[NOTE] No network segments defined — paths based on explicit relationships only.")
            lines.push("Use state_update add_segment to define network topology for reachability-based suggestions.")
            lines.push("")
          }

          if (reachableSegments.length > 0) {
            lines.push("Reachable network segments:")
            for (const seg of reachableSegments) {
              lines.push(
                `  ${seg.cidr}${seg.name ? ` (${seg.name})` : ""}${seg.pivot_host ? ` via ${seg.pivot_host}` : ""}`,
              )
            }
            lines.push("")
          }

          if (unreachableSegments.length > 0) {
            lines.push("Unreachable segments (need additional pivots):")
            for (const seg of unreachableSegments) {
              lines.push(`  ${seg.cidr}${seg.name ? ` (${seg.name})` : ""}`)
            }
          }

          return {
            title: `${topN.length} pivot targets`,
            metadata: { from: fromIp, suggestions: topN.length },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)
