/**
 * Client-side mirror of the FastAPI attack-graph engine
 * (app/services/graph.py, simulation.py, correlation.py).
 *
 * Keeping the same cost model and metrics here lets the demo UI run against
 * the fixture domain without a backend, while the API contracts stay
 * identical — swapping to live data is a data-source change only.
 */

import { EDGES, PRINCIPALS, type Edge, type Principal, type Severity } from "./data";

export const EDGE_COST: Record<string, number> = {
  MemberOf: 0.5,
  AdminTo: 1.0,
  HasDCSync: 1.0,
  HasSession: 1.5,
  GenericAll: 2.0,
  AddMember: 2.0,
  CanRDP: 2.0,
  GenericWrite: 2.5,
  ForceChangePassword: 2.5,
  WriteDacl: 3.0,
  WriteOwner: 3.0,
  GpLink: 3.0,
  AllowedToDelegate: 3.5,
};
export const DEFAULT_COST = 4.0;

const TIER0_NAMES = new Set([
  "domain admins",
  "enterprise admins",
  "administrators",
  "schema admins",
  "account operators",
  "backup operators",
  "domain controllers",
]);

export const DANGEROUS_EDGES = new Set([
  "GenericAll",
  "GenericWrite",
  "WriteDacl",
  "WriteOwner",
  "AddMember",
  "ForceChangePassword",
  "HasDCSync",
  "AllowedToDelegate",
]);

export interface GraphStep {
  sourceSid: string;
  sourceName: string;
  targetSid: string;
  targetName: string;
  edgeType: string;
  cost: number;
}

export interface GraphPath {
  id: string;
  sourceSid: string;
  sourceName: string;
  targetSid: string;
  targetName: string;
  hops: number;
  totalCost: number;
  severity: Severity;
  steps: GraphStep[];
}

export interface GraphMetrics {
  riskScore: number;
  attackPaths: number;
  tier0Exposure: number;
  reachablePrivileged: number;
  averagePathCost: number;
  shortestPathHops: number | null;
}

export const edgeId = (e: Edge) => `${e.sourceSid}|${e.edgeType}|${e.targetSid}`;

const cost = (edgeType: string) => EDGE_COST[edgeType] ?? DEFAULT_COST;

function severityFor(totalCost: number): Severity {
  if (totalCost <= 2) return "critical";
  if (totalCost <= 5) return "high";
  if (totalCost <= 9) return "medium";
  return "low";
}

/** Immutable, read-only view over a principal + edge set. */
export class AttackGraph {
  readonly principals = new Map<string, Principal>();
  readonly adjacency = new Map<string, Edge[]>();
  readonly reverse = new Map<string, Edge[]>();
  readonly edges: readonly Edge[];

  constructor(principals: readonly Principal[] = PRINCIPALS, edges: readonly Edge[] = EDGES) {
    for (const p of principals) this.principals.set(p.objectSid, p);
    const kept: Edge[] = [];
    for (const e of edges) {
      if (!this.principals.has(e.sourceSid) || !this.principals.has(e.targetSid)) continue;
      kept.push(e);
      const out = this.adjacency.get(e.sourceSid) ?? [];
      out.push(e);
      this.adjacency.set(e.sourceSid, out);
      const inb = this.reverse.get(e.targetSid) ?? [];
      inb.push(e);
      this.reverse.set(e.targetSid, inb);
    }
    this.edges = kept;
  }

  /** Never mutates this graph — returns a brand-new one without `ids`. */
  without(ids: readonly string[]): AttackGraph {
    const drop = new Set(ids);
    return new AttackGraph(
      [...this.principals.values()],
      this.edges.filter((e) => !drop.has(edgeId(e))),
    );
  }

  name(sid: string) {
    return this.principals.get(sid)?.samAccountName ?? sid;
  }

  tier0Sids(): string[] {
    return [...this.principals.values()]
      .filter((p) => p.domainController || TIER0_NAMES.has(p.samAccountName.toLowerCase()))
      .map((p) => p.objectSid);
  }

  /** Dijkstra over the abuse-cost model. */
  cheapestPath(sourceSid: string, targetSid: string): GraphPath | null {
    if (sourceSid === targetSid || !this.principals.has(sourceSid)) return null;
    const dist = new Map<string, number>([[sourceSid, 0]]);
    const prev = new Map<string, Edge>();
    const seen = new Set<string>();
    const queue: Array<[number, string]> = [[0, sourceSid]];

    while (queue.length) {
      queue.sort((a, b) => a[0] - b[0]);
      const next = queue.shift();
      if (!next) break;
      const [c, node] = next;
      if (seen.has(node)) continue;
      seen.add(node);
      if (node === targetSid) break;
      for (const edge of this.adjacency.get(node) ?? []) {
        const nc = c + cost(edge.edgeType);
        if (nc < (dist.get(edge.targetSid) ?? Infinity)) {
          dist.set(edge.targetSid, nc);
          prev.set(edge.targetSid, edge);
          queue.push([nc, edge.targetSid]);
        }
      }
    }

    const total = dist.get(targetSid);
    if (total === undefined) return null;

    const steps: GraphStep[] = [];
    let cursor = targetSid;
    while (prev.has(cursor)) {
      const edge = prev.get(cursor)!;
      steps.unshift({
        sourceSid: edge.sourceSid,
        sourceName: this.name(edge.sourceSid),
        targetSid: edge.targetSid,
        targetName: this.name(edge.targetSid),
        edgeType: edge.edgeType,
        cost: cost(edge.edgeType),
      });
      cursor = edge.sourceSid;
    }
    return {
      id: `${sourceSid}->${targetSid}`,
      sourceSid,
      sourceName: this.name(sourceSid),
      targetSid,
      targetName: this.name(targetSid),
      hops: steps.length,
      totalCost: Math.round(total * 100) / 100,
      severity: severityFor(total),
      steps,
    };
  }

  pathsToTier0(sourceSid: string, limit = 10): GraphPath[] {
    return this.tier0Sids()
      .map((t) => this.cheapestPath(sourceSid, t))
      .filter((p): p is GraphPath => p !== null)
      .sort((a, b) => a.totalCost - b.totalCost || a.hops - b.hops)
      .slice(0, limit);
  }

  allTier0Paths(limit = 500): GraphPath[] {
    const tier0 = new Set(this.tier0Sids());
    const paths: GraphPath[] = [];
    for (const p of this.principals.values()) {
      if (tier0.has(p.objectSid) || !p.enabled) continue;
      paths.push(...this.pathsToTier0(p.objectSid, 3));
    }
    return paths.sort((a, b) => a.totalCost - b.totalCost || a.hops - b.hops).slice(0, limit);
  }

  blastRadius(sid: string): Set<string> {
    const seen = new Set<string>();
    const queue = [sid];
    while (queue.length) {
      const node = queue.shift()!;
      for (const edge of this.adjacency.get(node) ?? []) {
        if (!seen.has(edge.targetSid)) {
          seen.add(edge.targetSid);
          queue.push(edge.targetSid);
        }
      }
    }
    seen.delete(sid);
    return seen;
  }

  exposure(sid: string): Set<string> {
    const seen = new Set<string>();
    const queue = [sid];
    while (queue.length) {
      const node = queue.shift()!;
      for (const edge of this.reverse.get(node) ?? []) {
        if (!seen.has(edge.sourceSid)) {
          seen.add(edge.sourceSid);
          queue.push(edge.sourceSid);
        }
      }
    }
    seen.delete(sid);
    return seen;
  }
}

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 25, high: 12, medium: 5, low: 2 };

/**
 * Same blended score as the backend: findings severity + graph exposure, so
 * remediating a relationship (which removes no finding) still lowers risk.
 */
export function measure(
  graph: AttackGraph,
  findings: readonly { severity: Severity }[],
): GraphMetrics {
  const principalCount = graph.principals.size || 1;
  const findingComponent =
    (findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0) / principalCount) * 12;

  const paths = graph.allTier0Paths();
  const exposed = new Set(paths.map((p) => p.sourceSid));
  const tier0 = new Set(graph.tier0Sids());
  const pathComponent = paths.reduce((sum, p) => sum + 6 / Math.max(p.totalCost, 0.5), 0);
  const exposureComponent = exposed.size * 3;

  const reachablePrivileged = new Set(
    [...exposed].flatMap((sid) => [...graph.blastRadius(sid)].filter((t) => tier0.has(t))),
  ).size;

  const raw = findingComponent * 0.55 + pathComponent * 0.9 + exposureComponent;
  return {
    riskScore: Math.max(0, Math.min(100, Math.round(raw))),
    attackPaths: paths.length,
    tier0Exposure: exposed.size,
    reachablePrivileged,
    averagePathCost: paths.length
      ? Math.round((paths.reduce((s, p) => s + p.totalCost, 0) / paths.length) * 100) / 100
      : 0,
    shortestPathHops: paths.length ? Math.min(...paths.map((p) => p.hops)) : null,
  };
}

export interface SimulationResult {
  before: GraphMetrics;
  after: GraphMetrics;
  removedEdges: Edge[];
  reason: string;
  riskReduction: number;
  riskReductionPct: number;
  pathsEliminated: number;
  tier0ExposureReduction: number;
  eliminatedPaths: GraphPath[];
  remainingPaths: GraphPath[];
  notice: string;
}

export const SIMULATION_NOTICE = "SIMULATION — No Active Directory changes were performed.";

/** Pure: builds a temporary graph, never touches the source graph or AD. */
export function simulateRemoval(
  graph: AttackGraph,
  edgeIds: readonly string[],
  reason = "Remove excessive privilege",
  findings: readonly { severity: Severity }[] = [],
): SimulationResult {
  const drop = new Set(edgeIds);
  const removedEdges = graph.edges.filter((e) => drop.has(edgeId(e)));
  const simulated = graph.without(edgeIds);

  const before = measure(graph, findings);
  const after = measure(simulated, findings);

  const beforePaths = graph.allTier0Paths();
  const afterPaths = simulated.allTier0Paths();
  const afterKeys = new Set(afterPaths.map((p) => p.id));

  const riskReduction = before.riskScore - after.riskScore;
  return {
    before,
    after,
    removedEdges,
    reason,
    riskReduction,
    riskReductionPct: before.riskScore
      ? Math.round((riskReduction / before.riskScore) * 1000) / 10
      : 0,
    pathsEliminated: Math.max(before.attackPaths - after.attackPaths, 0),
    tier0ExposureReduction: Math.max(before.tier0Exposure - after.tier0Exposure, 0),
    eliminatedPaths: beforePaths.filter((p) => !afterKeys.has(p.id)),
    remainingPaths: afterPaths,
    notice: SIMULATION_NOTICE,
  };
}

// --- endpoint → identity correlation ------------------------------------
const SESSION_EDGES = ["HasSession", "CanRDP", "AdminTo"];
export const IDENTITY_UNAVAILABLE = "Identity correlation unavailable";

export interface CompromiseImpact {
  endpoint: string;
  endpointSid: string | null;
  status: string;
  identity: string | null;
  identitySid: string | null;
  identitySource: string;
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  riskScore: number;
  blastRadius: {
    users: number;
    groups: number;
    computers: number;
    privilegedTargets: number;
    total: number;
  };
  tier0Exposed: boolean;
  attackPathCount: number;
  shortestPath: string[];
  shortestPathHops: number | null;
  paths: GraphPath[];
  notes: string[];
}

const normalizeHost = (h: string) => h.trim().toLowerCase().split(".")[0]!.replace(/\$$/, "");

export function findComputer(graph: AttackGraph, hostname: string): Principal | null {
  const needle = normalizeHost(hostname);
  for (const p of graph.principals.values()) {
    if (p.type !== "computer") continue;
    if (normalizeHost(p.samAccountName) === needle || normalizeHost(p.displayName) === needle) {
      return p;
    }
  }
  return null;
}

export function correlateIdentity(
  graph: AttackGraph,
  computerSid: string,
  hint?: string | null,
): [Principal | null, string] {
  if (hint) {
    const needle = hint.trim().toLowerCase();
    const match = [...graph.principals.values()].find(
      (p) => p.samAccountName.toLowerCase() === needle,
    );
    if (match) return [match, "reported_logon"];
  }
  const inbound = graph.reverse.get(computerSid) ?? [];
  for (const edge of inbound) {
    if (!SESSION_EDGES.includes(edge.edgeType)) continue;
    const p = graph.principals.get(edge.sourceSid);
    if (p?.type === "user") return [p, `graph:${edge.edgeType}`];
  }
  for (const edge of inbound) {
    const p = graph.principals.get(edge.sourceSid);
    if (p?.type === "user") return [p, `graph:${edge.edgeType}`];
  }
  return [null, "none"];
}

function riskLevel(score: number): CompromiseImpact["risk"] {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

export function analyzeEndpoint(
  graph: AttackGraph,
  hostname: string,
  status = "unknown",
  loggedOnUser?: string | null,
): CompromiseImpact {
  const notes: string[] = [];
  const computer = findComputer(graph, hostname);
  if (!computer) notes.push("No matching AD computer object; endpoint-level data only.");

  let identity: Principal | null = null;
  let identitySource = "none";
  if (computer) {
    [identity, identitySource] = correlateIdentity(graph, computer.objectSid, loggedOnUser);
  } else if (loggedOnUser) {
    const needle = loggedOnUser.trim().toLowerCase();
    identity =
      [...graph.principals.values()].find((p) => p.samAccountName.toLowerCase() === needle) ?? null;
    identitySource = identity ? "reported_logon" : "none";
  }

  const pivot = identity ?? computer;
  if (!pivot) {
    return {
      endpoint: hostname,
      endpointSid: null,
      status,
      identity: null,
      identitySid: null,
      identitySource: "none",
      risk: "LOW",
      riskScore: 0,
      blastRadius: { users: 0, groups: 0, computers: 0, privilegedTargets: 0, total: 0 },
      tier0Exposed: false,
      attackPathCount: 0,
      shortestPath: [],
      shortestPathHops: null,
      paths: [],
      notes: [...notes, IDENTITY_UNAVAILABLE],
    };
  }
  if (!identity) notes.push(IDENTITY_UNAVAILABLE);

  const reachable = graph.blastRadius(pivot.objectSid);
  const tier0 = new Set(graph.tier0Sids());
  const counts = { users: 0, groups: 0, computers: 0 };
  for (const sid of reachable) {
    const p = graph.principals.get(sid);
    if (p?.type === "user") counts.users += 1;
    if (p?.type === "group") counts.groups += 1;
    if (p?.type === "computer") counts.computers += 1;
  }
  const privilegedTargets = [...reachable].filter((s) => tier0.has(s)).length;

  const paths = graph.pathsToTier0(pivot.objectSid, 25);
  const shortest = paths.reduce<GraphPath | null>(
    (best, p) => (!best || p.hops < best.hops || (p.hops === best.hops && p.totalCost < best.totalCost) ? p : best),
    null,
  );

  let score = 0;
  score += Math.min(reachable.size, 20) * 2;
  score += privilegedTargets * 12;
  score += Math.min(paths.length, 8) * 4;
  if (shortest) score += Math.max(0, 20 - (shortest.hops - 1) * 5);
  if (pivot.adminCount) score += 10;
  if (status === "malicious" || status === "compromised") score += 20;
  else if (status === "suspicious") score += 10;
  score = Math.max(0, Math.min(100, score));

  return {
    endpoint: computer?.displayName ?? hostname,
    endpointSid: computer?.objectSid ?? null,
    status,
    identity: identity?.samAccountName ?? null,
    identitySid: identity?.objectSid ?? null,
    identitySource,
    risk: riskLevel(score),
    riskScore: score,
    blastRadius: { ...counts, privilegedTargets, total: reachable.size },
    tier0Exposed: privilegedTargets > 0,
    attackPathCount: paths.length,
    shortestPath: shortest ? [shortest.sourceName, ...shortest.steps.map((s) => s.targetName)] : [],
    shortestPathHops: shortest?.hops ?? null,
    paths: paths.slice(0, 10),
    notes,
  };
}

/** Live graph over the current fixture snapshot. */
export const liveGraph = new AttackGraph();
