/**
 * Typed client for the ADShield FastAPI backend.
 *
 * Every network call in the app goes through this module, so pointing the UI
 * at another backend is a single environment-variable change
 * (`VITE_API_BASE_URL`). Nothing here contains credentials.
 */

import type {
  AttackPath,
  Edge,
  Finding,
  Principal,
  PrincipalType,
  Role,
  SessionUser,
  Severity,
} from "./data";
import type { CompromiseImpact, GraphPath } from "./graph";

export const API_BASE_URL: string = (
  (import.meta.env["VITE_API_BASE_URL"] as string | undefined) ?? "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const TOKEN_KEY = "adshield.token";

// --- token handling ------------------------------------------------------
export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable — session stays in memory only */
  }
}

// --- errors --------------------------------------------------------------
export type ApiErrorKind =
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "unavailable"
  | "network"
  | "server";

export class ApiError extends Error {
  readonly status: number;
  readonly kind: ApiErrorKind;

  constructor(status: number, kind: ApiErrorKind, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.kind = kind;
  }
}

/** Emitted when the backend rejects the stored token, so the UI can sign out. */
export const AUTH_EXPIRED_EVENT = "adshield:auth-expired";

function classify(status: number): ApiErrorKind {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 503 || status === 502 || status === 504) return "unavailable";
  return "server";
}

const FRIENDLY: Record<ApiErrorKind, string> = {
  unauthorized: "Your session has expired. Please sign in again.",
  forbidden: "Your role does not grant access to this data.",
  not_found: "The requested resource is not available on the backend.",
  unavailable: "The directory service or backend is unavailable.",
  network: `Cannot reach the ADShield backend at ${API_BASE_URL}.`,
  server: "The backend returned an unexpected error.",
};

async function readDetail(res: Response): Promise<string | null> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
  } catch {
    /* non-JSON error body — never surfaced to the user */
  }
  return null;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  auth?: boolean;
  formData?: FormData;
  signal?: AbortSignal;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, auth = true, formData, signal } = opts;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  const init: RequestInit = { method, headers };
  if (signal) init.signal = signal;
  if (formData) init.body = formData;
  else if (body !== undefined) init.body = JSON.stringify(body);

  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}/api${path}`, init);

  } catch {
    throw new ApiError(0, "network", FRIENDLY.network);
  }

  if (!res.ok) {
    const kind = classify(res.status);
    if (kind === "unauthorized" && auth) {
      setToken(null);
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
      }
    }
    // Backend detail strings are sanitised; stack traces are never shown.
    const detail = await readDetail(res);
    throw new ApiError(res.status, kind, detail || FRIENDLY[kind]);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// --- backend response shapes (mirror app/schemas) ------------------------
export interface UserProfileDto {
  object_sid: string;
  sam_account_name: string;
  display_name: string;
  email: string | null;
  role: Role;
  permissions: string[];
}

export interface LoginResponseDto {
  access_token: string;
  token_type: string;
  expires_at: string;
  user: UserProfileDto;
}

export interface AdHealthDto {
  connected: boolean;
  connector: string;
  domain: string;
  server: string;
  protocol: string;
  port: number;
  base_dn: string;
  latency_ms: number | null;
  error: string | null;
}

export interface CollectionStatsDto {
  status: string;
  connector: string;
  domain: string;
  users: number;
  groups: number;
  computers: number;
  gpos: number;
  ous: number;
  relationships: number;
  findings: number;
  risk_score: number;
  duration_ms: number;
  collected_at: string;
}

export interface PrincipalDto {
  object_sid: string;
  dn: string;
  sam_account_name: string;
  display_name: string;
  principal_type: string;
  enabled: boolean;
  is_admin_count: boolean;
  is_domain_controller: boolean;
  spns: string[];
  password_last_set: string | null;
  last_logon: string | null;
  operating_system: string | null;
  description: string | null;
}

export interface FindingDto {
  id: string;
  rule: string;
  title: string;
  severity: string;
  principal_sid: string;
  principal_name: string;
  description: string;
  remediation: string;
  mitre_technique: string;
}

export interface PathStepDto {
  source_sid: string;
  source_name: string;
  target_sid: string;
  target_name: string;
  edge_type: string;
  cost: number;
}

export interface AttackPathDto {
  source_sid: string;
  source_name: string;
  target_sid: string;
  target_name: string;
  hops: number;
  total_cost: number;
  severity: string;
  steps: PathStepDto[];
}

export interface RemovableEdgeDto {
  edge_id: string;
  source_sid: string;
  source_name: string;
  target_sid: string;
  target_name: string;
  edge_type: string;
  note: string | null;
}

export interface GraphMetricsDto {
  risk_score: number;
  attack_paths: number;
  tier0_exposure: number;
  reachable_privileged: number;
  average_path_cost: number;
  shortest_path_hops: number | null;
}

export interface SimulationDto {
  before: GraphMetricsDto;
  after: GraphMetricsDto;
  simulation: Record<string, unknown>;
  risk_reduction: number;
  risk_reduction_pct: number;
  paths_eliminated: number;
  tier0_exposure_reduction: number;
  eliminated_paths: AttackPathDto[];
  remaining_paths: AttackPathDto[];
  notice: string;
}

export interface EndpointDto {
  endpoint_id: string;
  hostname: string;
  operating_system: string | null;
  domain_controller: boolean;
  identity: string | null;
  identity_source: string;
}

export interface CompromiseImpactDto {
  endpoint: string;
  endpoint_sid: string | null;
  status: string;
  identity: string | null;
  identity_sid: string | null;
  identity_source: string;
  risk: string;
  risk_score: number;
  blast_radius: {
    users: number;
    groups: number;
    computers: number;
    privileged_targets: number;
    total: number;
  };
  tier0_exposed: boolean;
  attack_path_count: number;
  shortest_path: string[];
  shortest_path_hops: number | null;
  paths: AttackPathDto[];
  notes: string[];
}

export interface DashboardDto {
  domain: string;
  risk_score: number;
  collected_at: string;
  users: number;
  groups: number;
  computers: number;
  gpos: number;
  findings_by_severity: { critical: number; high: number; medium: number; low: number };
  tier0_exposed_principals: number;
  critical_paths: AttackPathDto[];
  top_rules: { rule: string; count: number }[];
}

interface Paged<T> {
  total: number;
  page: number;
  page_size: number;
  items: T[];
}

// --- mappers (backend snake_case -> existing frontend models) -------------
const daysSince = (iso: string | null): number | null => {
  if (!iso) return null;
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return null;
  return Math.max(0, Math.round((Date.now() - then) / 86_400_000));
};

const asSeverity = (value: string): Severity =>
  value === "critical" || value === "high" || value === "medium" || value === "low"
    ? value
    : "low";

const asPrincipalType = (value: string): PrincipalType =>
  value === "user" || value === "group" || value === "computer" || value === "gpo"
    ? value
    : "user";

export function toPrincipal(dto: PrincipalDto): Principal {
  return {
    objectSid: dto.object_sid,
    samAccountName: dto.sam_account_name,
    displayName: dto.display_name,
    type: asPrincipalType(dto.principal_type),
    enabled: dto.enabled,
    adminCount: dto.is_admin_count,
    domainController: dto.is_domain_controller,
    spns: dto.spns,
    passwordAgeDays: daysSince(dto.password_last_set),
    lastLogonDays: daysSince(dto.last_logon),
    ...(dto.operating_system ? { os: dto.operating_system } : {}),
    ...(dto.description ? { description: dto.description } : {}),
  };
}

export function toFinding(dto: FindingDto): Finding {
  return {
    id: dto.id,
    rule: dto.rule,
    title: dto.title,
    severity: asSeverity(dto.severity),
    principalSid: dto.principal_sid,
    principalName: dto.principal_name,
    description: dto.description,
    remediation: dto.remediation,
    mitre: dto.mitre_technique,
  };
}

export function toAttackPath(dto: AttackPathDto): AttackPath {
  return {
    id: `${dto.source_sid}->${dto.target_sid}:${dto.hops}`,
    sourceName: dto.source_name,
    targetName: dto.target_name,
    hops: dto.hops,
    totalCost: Math.round(dto.total_cost * 100) / 100,
    severity: asSeverity(dto.severity),
    steps: dto.steps.map((s) => ({
      sourceName: s.source_name,
      targetName: s.target_name,
      edgeType: s.edge_type,
      cost: s.cost,
    })),
  };
}

export function toGraphPath(dto: AttackPathDto): GraphPath {
  return {
    id: `${dto.source_sid}->${dto.target_sid}:${dto.hops}`,
    sourceSid: dto.source_sid,
    sourceName: dto.source_name,
    targetSid: dto.target_sid,
    targetName: dto.target_name,
    hops: dto.hops,
    totalCost: Math.round(dto.total_cost * 100) / 100,
    severity: asSeverity(dto.severity),
    steps: dto.steps.map((s) => ({
      sourceSid: s.source_sid,
      sourceName: s.source_name,
      targetSid: s.target_sid,
      targetName: s.target_name,
      edgeType: s.edge_type,
      cost: s.cost,
    })),
  };
}

export function toEdge(dto: RemovableEdgeDto): Edge {
  return {
    sourceSid: dto.source_sid,
    targetSid: dto.target_sid,
    edgeType: dto.edge_type,
    ...(dto.note ? { note: dto.note } : {}),
  };
}

export function toSessionUser(dto: UserProfileDto): SessionUser {
  return {
    samAccountName: dto.sam_account_name,
    displayName: dto.display_name,
    objectSid: dto.object_sid,
    role: dto.role,
    permissions: dto.permissions,
  };
}

export function toCompromiseImpact(dto: CompromiseImpactDto): CompromiseImpact {
  const risk = dto.risk.toUpperCase();
  return {
    endpoint: dto.endpoint,
    endpointSid: dto.endpoint_sid,
    status: dto.status,
    identity: dto.identity,
    identitySid: dto.identity_sid,
    identitySource: dto.identity_source,
    risk:
      risk === "CRITICAL" || risk === "HIGH" || risk === "MEDIUM" ? risk : "LOW",
    riskScore: dto.risk_score,
    blastRadius: {
      users: dto.blast_radius.users,
      groups: dto.blast_radius.groups,
      computers: dto.blast_radius.computers,
      privilegedTargets: dto.blast_radius.privileged_targets,
      total: dto.blast_radius.total,
    },
    tier0Exposed: dto.tier0_exposed,
    attackPathCount: dto.attack_path_count,
    shortestPath: dto.shortest_path,
    shortestPathHops: dto.shortest_path_hops,
    paths: dto.paths.map(toGraphPath),
    notes: dto.notes,
  };
}

// --- endpoint functions --------------------------------------------------
export const api = {
  login: (username: string, password: string) =>
    request<LoginResponseDto>("/auth/login", {
      method: "POST",
      auth: false,
      body: { username, password },
    }),

  me: () => request<UserProfileDto>("/auth/me"),

  adHealth: () => request<AdHealthDto>("/ad/health"),

  adCollect: () => request<CollectionStatsDto>("/ad/collect", { method: "POST" }),

  dashboard: () => request<DashboardDto>("/dashboard"),

  assets: (params: { type?: string; q?: string; page_size?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.type && params.type !== "all") qs.set("type", params.type);
    if (params.q) qs.set("q", params.q);
    qs.set("page_size", String(params.page_size ?? 200));
    return request<Paged<PrincipalDto>>(`/assets?${qs.toString()}`);
  },

  findings: (params: { severity?: string; page_size?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.severity && params.severity !== "all") qs.set("severity", params.severity);
    qs.set("page_size", String(params.page_size ?? 200));
    return request<Paged<FindingDto>>(`/findings?${qs.toString()}`);
  },

  myHygiene: () => request<FindingDto[]>("/me/hygiene"),

  attackPaths: () => request<AttackPathDto[]>("/attack-paths"),

  removableEdges: () => request<RemovableEdgeDto[]>("/attack-paths/edges"),

  simulateRemediation: (edgeIds: string[], reason = "Analyst remediation candidate") =>
    request<SimulationDto>("/attack-paths/simulate-remediation", {
      method: "POST",
      body: { edge_ids: edgeIds, action: "remove", reason },
    }),

  endpoints: () => request<EndpointDto[]>("/endpoints"),

  compromiseImpact: (endpointId: string, status = "suspicious", loggedOnUser?: string | null) => {
    const qs = new URLSearchParams({ status });
    if (loggedOnUser) qs.set("logged_on_user", loggedOnUser);
    return request<CompromiseImpactDto>(
      `/endpoints/${encodeURIComponent(endpointId)}/compromise-impact?${qs.toString()}`,
    );
  },

  whatIfIdentity: (identity: string, status = "compromised") =>
    request<CompromiseImpactDto>("/endpoints/what-if", {
      method: "POST",
      body: { identity, status },
    }),

  scanFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<Record<string, unknown>>("/endpoint/scan-file", {
      method: "POST",
      formData: form,
    });
  },
};

/** Human-readable message for any thrown value — never a stack trace. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "Something went wrong while talking to the backend.";
}
