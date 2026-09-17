/**
 * Warden / Warden X API types.
 *
 * Compatibility rules:
 * - v1 shapes (Scan, Signal, Policy, ScanSummary, ScanStats, Page) keep every v1 field with its
 *   v1 type. Every Warden X field added to a v1 response is OPTIONAL, because scans recorded
 *   before Warden X (and a backend that has not been upgraded yet) do not carry them.
 * - Shapes follow .warden-x/SPEC.md sections 3-13 and the backend contracts that exist today
 *   (analysis/findings.py, analysis/risk.py, intel/models.py, graph/engine.py, events/types.py).
 * - Where the spec leaves a shape open (attack chains, provenance summary, system and model
 *   info), every field is optional and the UI must treat it as possibly absent.
 * - All string content in these objects can be attacker-influenced (package metadata, file
 *   names, evidence). Render it as text only; never as HTML.
 */

// ---------------------------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------------------------

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const DECISIONS = ["allow", "warn", "block"] as const;
export type Decision = (typeof DECISIONS)[number];

/** Policy environments (backend `db.models.ENVIRONMENTS`). */
export const ENVIRONMENTS = ["development", "staging", "production"] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

export const USER_ROLES = ["admin", "security_analyst", "developer", "auditor", "read_only"] as const;
/** Warden X role names (SPEC section 5/6). */
export type UserRole = (typeof USER_ROLES)[number];
/** v1 role names. The server maps analyst -> security_analyst and viewer -> read_only. */
export type LegacyRole = "analyst" | "viewer";
/** A role as the API may return it: Warden X names, or v1 names from a backend not yet migrated. */
export type Role = UserRole | LegacyRole;

/** Finding categories (backend `analysis.findings.Category`). */
export const FINDING_CATEGORIES = [
  "malicious_behavior",
  "capability",
  "install_time_execution",
  "obfuscation",
  "credential_access",
  "typosquatting",
  "dependency_confusion",
  "ioc",
  "secret",
  "vulnerability",
  "provenance",
  "reputation",
  "behavior_drift",
  "attack_chain",
  "suspicious_artifact",
  "integrity",
  "code_weakness",
  "misconfiguration",
  "dependency_hygiene",
  "pipeline",
  "other",
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

/** Security event types as stored by the backend (lower snake case, `events/types.py`). */
export const EVENT_TYPES = [
  "package_scanned",
  "package_blocked",
  "risk_increased",
  "risk_decreased",
  "vulnerability_discovered",
  "kev_added",
  "behavior_drift_detected",
  "maintainer_changed",
  "provenance_changed",
  "new_release_detected",
  "policy_violation",
  "exception_created",
  "exception_approved",
  "exception_rejected",
  "exception_revoked",
  "exception_expired",
  "sbom_generated",
  "project_scanned",
  "container_scanned",
  "dependency_graph_changed",
  "monitor_error",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

// ---------------------------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------------------------

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface PageParams {
  limit?: number;
  offset?: number;
}

/** Error body shape used by every API error (SPEC section 13). */
export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id?: string | null;
  };
}

// ---------------------------------------------------------------------------------------------
// Auth and users
// ---------------------------------------------------------------------------------------------

/**
 * A user account (backend `schemas/user.py` UserOut), returned by GET /auth/me, GET /users,
 * PATCH /users/{id} and POST /auth/register. The server never includes the password hash or any
 * token in it.
 */
export interface User {
  id: string;
  /** Stored lower case. */
  email: string;
  /** A Warden X server returns the canonical name; a v1 server may still return analyst or viewer. */
  role: Role;
  is_active: boolean;
  created_at: string;
  /** Effective permissions of the role (informational; the server enforces them). Absent on v1. */
  permissions?: string[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

/**
 * Body of PATCH /users/{id} (user:manage). At least one field is required and unknown fields are
 * rejected. The server answers 409 with code "last_admin" when the change would leave no active admin.
 */
export type UserUpdate = { role: UserRole; is_active?: boolean } | { role?: UserRole; is_active: boolean };

/**
 * Body of POST /auth/register (user:manage, backend `schemas/auth.py` RegisterRequest). Unknown
 * fields are rejected; the server lower-cases the email and answers 409 when it is already taken.
 */
export interface UserRegistration {
  email: string;
  /** 12 to 256 characters, counted as Unicode code points. */
  password: string;
  /** The server defaults to read_only. */
  role?: UserRole;
}

/** GET /users query. The server orders users by creation time, then email. */
export interface ListUsersParams extends PageParams {
  role?: UserRole;
  is_active?: boolean;
  /** Case-insensitive email substring, at most 320 characters. */
  q?: string;
}

// ---------------------------------------------------------------------------------------------
// Findings (SPEC section 1 "Finding conventions"; backend analysis/findings.py)
// ---------------------------------------------------------------------------------------------

/** v1 signal. Every Warden X finding is also a valid Signal. */
export interface Signal {
  code: string;
  severity: Severity;
  weight: number;
  message: string;
  evidence: Record<string, unknown>;
}

/** Where a finding was observed. Analyzers only populate positions they really know. */
export interface Location {
  file: string | null;
  line: number | null;
  column?: number | null;
  end_line?: number | null;
  snippet?: string | null;
}

export type ComplianceFramework = "cwe" | "attack" | "owasp_top10_2021" | "nist_ssdf" | "slsa" | "openssf";
export type ComplianceMappings = Partial<Record<ComplianceFramework, string[]>>;

/**
 * Warden X finding. Extends the v1 Signal; the extra keys are optional because v1 scans
 * only stored code/severity/weight/message/evidence.
 */
export interface Finding extends Signal {
  capability?: string | null;
  /** Deterministic finding id. Absent or null on v1 scans. */
  finding_id?: string | null;
  /** 0.0-1.0 likelihood that the finding is a true positive (independent of severity). */
  confidence?: number | null;
  category?: string | null;
  title?: string | null;
  analyzer?: string | null;
  analyzer_version?: string | null;
  location?: Location | null;
  cwe?: string[] | null;
  /** MITRE ATT&CK technique ids, e.g. "T1027" or "T1195.001". */
  attack?: string[] | null;
  remediation?: string | null;
  references?: string[] | null;
  /** Data source, e.g. "static-analysis", "registry-metadata", "external-tool:semgrep". */
  provenance?: string | null;
  /** finding_ids this finding was derived from (attack chains, drift findings). */
  related?: string[] | null;
  compliance?: ComplianceMappings | null;
}

// ---------------------------------------------------------------------------------------------
// Risk Engine 2.0 (SPEC section 4; backend analysis/risk.py)
// ---------------------------------------------------------------------------------------------

export const RISK_DIMENSIONS = [
  "behavioral",
  "vulnerability",
  "provenance",
  "reputation",
  "dependency",
  "integrity",
  "anomaly",
  "exploitability",
  "blast_radius",
] as const;
export type RiskDimensionName = (typeof RISK_DIMENSIONS)[number];

export interface RiskDimension {
  /** 0-100, or null when the dimension could not be assessed (unknown, not zero). */
  score: number | null;
  confidence: number;
  /** finding_ids that contributed to the score. */
  contributors: string[];
  rationale: string | null;
}

export interface RiskFloor {
  rule: string;
  minimum?: number;
  previous_score?: number;
  raised?: boolean;
  codes?: string[];
  finding_ids?: string[];
}

export interface RiskBreakdown {
  method: string;
  final_score: number;
  severity: Severity;
  confidence: number;
  malicious_risk: number;
  rule_score: number;
  /** 0 both when the model scored 0 and when no model ran; lib/scan.ts mlModelUsed tells them apart. */
  ml_score: number;
  /** null when vulnerability intelligence was unavailable (unknown, not zero). */
  vulnerability_risk: number | null;
  dimensions: Partial<Record<RiskDimensionName, RiskDimension>>;
  floors_applied: RiskFloor[];
}

// ---------------------------------------------------------------------------------------------
// Attack chains (SPEC section 3 step 4)
//
// The spec does not fix the attack-chain shape, so this is the frontend's proposed contract.
// Everything except `steps` is optional so the view degrades if the final backend shape omits
// a field.
// ---------------------------------------------------------------------------------------------

export interface AttackChainStep {
  /** 1-based position in the chain; when absent, array order is used. */
  order?: number;
  technique_id?: string | null;
  technique_name?: string | null;
  tactic?: string | null;
  description?: string | null;
  finding_ids: string[];
}

export interface AttackChain {
  id?: string;
  title?: string | null;
  summary?: string | null;
  severity?: Severity;
  confidence?: number;
  /** finding_id of the derived ATTACK_CHAIN finding, when one was emitted. */
  finding_id?: string | null;
  steps: AttackChainStep[];
}

// ---------------------------------------------------------------------------------------------
// Pipeline and intelligence (SPEC sections 3 and 8)
// ---------------------------------------------------------------------------------------------

export const ANALYZER_RUN_STATUSES = ["ok", "error", "timeout", "skipped", "unavailable"] as const;
export type AnalyzerRunStatus = (typeof ANALYZER_RUN_STATUSES)[number];

export interface AnalyzerRun {
  name: string;
  version: string | null;
  status: AnalyzerRunStatus;
  duration_ms: number | null;
  finding_count: number;
  detail: string | null;
}

export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low" | "unknown";

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string | null;
  severity: VulnerabilitySeverity;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_version: string | null;
  published: string | null;
  modified: string | null;
  affected_ranges: Record<string, unknown>[];
  fixed_versions: string[];
  references: string[];
  kev: boolean;
  kev_date_added: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  /** e.g. "osv", "cisa-kev", "first-epss", "nvd". */
  sources: string[];
  withdrawn: boolean | string | null;
  database_specific_severity: string | null;
}

/** "not_run" is reported when no vulnerability analyzer ran for the scan. */
export type IntelStatusValue = "ok" | "partial" | "unavailable" | "disabled" | "not_run";

export interface IntelStatus {
  status: IntelStatusValue;
  /** Per-source outcome: ok | partial | error | disabled | skipped | unsupported. */
  sources?: Record<string, string>;
  fetched_at?: string | null;
  reason?: string | null;
  finding_ids?: string[];
}

/**
 * Package provenance summary (PEP 740 attestations, trusted publishing, hash verification).
 * The provenance analyzer's output shape is not fixed by the spec yet, so every field is
 * optional; unknown extra keys are rendered generically as plain text.
 */
export interface ProvenanceSummary {
  status?: string | null;
  attested?: boolean | null;
  publisher?: {
    kind?: string | null;
    repository?: string | null;
    workflow?: string | null;
    environment?: string | null;
  } | null;
  source_repository?: string | null;
  hash_verified?: boolean | null;
  detail?: string | null;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------------------------
// Policy (SPEC section 11)
// ---------------------------------------------------------------------------------------------

export interface PolicyDecisionReason {
  rule: string;
  detail: string;
  finding_ids: string[];
}

export interface VulnerabilityRule {
  known_exploited?: boolean;
  min_severity?: VulnerabilitySeverity | null;
  min_cvss?: number | null;
  min_epss?: number | null;
}

export interface PolicyDocument {
  apiVersion: string;
  kind: "Policy";
  metadata: { name: string; environment?: string };
  spec: {
    thresholds?: { warn?: number; block?: number };
    min_package_age_days?: number;
    deny?: {
      packages?: string[];
      codes?: string[];
      categories?: string[];
      capabilities?: string[];
      vulnerabilities?: VulnerabilityRule;
      min_confidence?: number;
    };
    warn?: { codes?: string[]; categories?: string[]; vulnerabilities?: VulnerabilityRule };
    require?: { provenance?: string | null; hash_verified?: boolean; sbom?: boolean };
    allow?: { packages?: string[] };
    exceptions?: {
      package: string;
      version?: string;
      codes?: string[];
      categories?: string[];
      expires?: string;
      reason?: string;
      approved_by?: string;
    }[];
  };
}

export interface Policy {
  id: string;
  name: string;
  is_active: boolean;
  warn_threshold: number;
  block_threshold: number;
  min_package_age_days: number;
  blocked_capabilities: string[];
  allowlist: string[];
  denylist: string[];
  created_at: string;
  updated_at: string | null;
  // Warden X additions (optional for v1 backends).
  environment?: string;
  document?: PolicyDocument | null;
  version?: number;
}

/**
 * Body of POST /policies and PUT /policies/{id}. The policy-as-code `document` is read-only on
 * the current server, so it is not part of the write shape. warn_threshold <= block_threshold.
 */
export interface PolicyWrite {
  name: string;
  warn_threshold: number;
  block_threshold: number;
  min_package_age_days: number;
  blocked_capabilities: string[];
  allowlist: string[];
  denylist: string[];
  /** On update, omit to keep the policy's current environment. */
  environment?: Environment;
}

export interface PolicyValidationResult {
  valid: boolean;
  errors: { path?: string | null; message: string }[];
}

// Policy exceptions: backend app/schemas/exception.py and app/api/routers/policies.py.

/**
 * Effective exception status (backend `ExceptionStatusOut`). "expired" is never stored: the server
 * reports it for a pending or approved exception whose expires_at has passed. Consequently an
 * "approved" exception is always one still in force (`active` is true exactly when status is
 * "approved"), and there is no separate "active" status or filter.
 */
export const EXCEPTION_STATUSES = ["pending", "approved", "rejected", "revoked", "expired"] as const;
export type ExceptionStatus = (typeof EXCEPTION_STATUSES)[number];

/** Backend `ExceptionOut`: list items and the response of every transition. */
export interface PolicyException {
  id: string;
  /** null = global exception (applies to every policy). */
  policy_id: string | null;
  /** PEP 503-normalised package name. */
  package: string;
  /** Normalised PEP 440 specifier set, or null for every version. */
  version_spec: string | null;
  /** Upper-case finding codes. */
  codes: string[];
  /** Finding categories (FINDING_CATEGORIES values). */
  categories: string[];
  /** null = every environment. */
  environment: string | null;
  justification: string;
  requested_by: string;
  /** Who approved or rejected the request. */
  approved_by: string | null;
  /** Who revoked or withdrew the exception. */
  revoked_by: string | null;
  status: ExceptionStatus;
  /** True only when approved and not expired. */
  active: boolean;
  expires_at: string;
  created_at: string;
  /** When the request was approved or rejected. */
  decided_at: string | null;
  revoked_at: string | null;
}

/** Backend `ExceptionTransition`: optional body of approve / reject / revoke (comment at most 500 characters). */
export interface ExceptionTransition {
  comment?: string | null;
}

/**
 * Backend `ExceptionCreate` (unknown fields are rejected). The server normalises the package name and
 * version specifier, and requires expires_at in the future and at most 365 days ahead.
 */
export interface PolicyExceptionCreate {
  package: string;
  version_spec?: string | null;
  codes?: string[];
  categories?: string[];
  /** Omit for a global exception. When given, `environment` must match the policy's environment. */
  policy_id?: string | null;
  /** Omit to apply in every environment. */
  environment?: Environment | null;
  justification: string;
  /** ISO 8601 date-time. */
  expires_at: string;
}

/** Query of GET /policies/exceptions (newest first). */
export interface ListExceptionsParams extends PageParams {
  status?: ExceptionStatus;
  /** Exact package name, matched after PEP 503 normalisation. An invalid name is rejected with 422. */
  package?: string;
  policy_id?: string;
  /** Exact environment match: global exceptions (no environment) are not included. */
  environment?: Environment;
}

// ---------------------------------------------------------------------------------------------
// Scans (SPEC sections 3 and 13)
// ---------------------------------------------------------------------------------------------

export interface Scan {
  id: string;
  ecosystem: string;
  package_name: string;
  version: string;
  rule_score: number;
  /** 0 both for a real score of 0 and when no model ran; lib/scan.ts mlModelUsed tells them apart. */
  ml_score: number;
  risk_score: number;
  severity: Severity;
  decision: Decision;
  matched_policy_rules: string[];
  feature_vector: Record<string, number>;
  analyzer_version: string;
  duration_ms: number;
  created_at: string;
  signals: Finding[];
  // --- Warden X additions: optional, absent on v1 scans ---------------------------------
  risk?: RiskBreakdown | null;
  attack_chains?: AttackChain[] | null;
  analyzer_runs?: AnalyzerRun[] | null;
  package_intel?: Record<string, unknown> | null;
  provenance?: ProvenanceSummary | null;
  vulnerabilities?: Vulnerability[] | null;
  intel_status?: IntelStatus | null;
  model_version?: string | null;
  policy_reasons?: PolicyDecisionReason[] | null;
  environment?: string | null;
  vulnerability_risk?: number | null;
  malicious_risk?: number | null;
  explanation?: Record<string, unknown> | null;
  scan_options?: Record<string, unknown> | null;
}

export interface ScanSummary {
  id: string;
  ecosystem: string;
  package_name: string;
  version: string;
  risk_score: number;
  severity: Severity;
  decision: Decision;
  created_at: string;
  // Warden X additions.
  environment?: string | null;
  vulnerability_risk?: number | null;
  malicious_risk?: number | null;
}

export interface ScanStats {
  total: number;
  by_decision: Record<Decision, number>;
  by_severity: Record<Severity, number>;
  blocked_last_30d: number;
  avg_risk_score: number;
  top_signals: { code: string; count: number }[];
}

/** Options recorded on a Warden X scan (`scan_options`). POST /scans does not accept them today. */
export interface ScanOptions {
  offline?: boolean;
  intel?: boolean;
  provenance?: boolean;
}

export interface ScanRequest {
  ecosystem?: "pypi";
  name: string;
  /** Omit (or null) to analyse the latest release. */
  version?: string | null;
  /** Policy environment; the server defaults to production. */
  environment?: Environment;
}

export interface ListScansParams extends PageParams {
  decision?: Decision;
  severity?: Severity;
  /** Case-insensitive package-name substring. */
  q?: string;
  environment?: Environment;
}

export const REPORT_FORMATS = ["json", "markdown", "html", "sarif"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];
export type SbomFormat = "cyclonedx" | "spdx";

// ---------------------------------------------------------------------------------------------
// Packages (SPEC section 13)
// ---------------------------------------------------------------------------------------------

export interface PackageVerdict {
  scan_id: string;
  version: string;
  environment: string;
  decision: Decision;
  risk_score: number;
  severity: Severity;
  scanned_at: string;
}

export interface PackageAdvisory {
  id: string;
  severity: string | null;
  kev: boolean;
  /** Versions of this package whose stored verdict lists the advisory. */
  versions: string[];
}

/** GET /packages/{ecosystem}/{name} (backend api/routers/packages.py). Database only. */
export interface PackageOverview {
  ecosystem: string;
  name: string;
  latest_verdict: (PackageVerdict & { package_intel: Record<string, unknown> | null; provenance: Record<string, unknown> | null }) | null;
  verdicts: PackageVerdict[];
  vulnerabilities: PackageAdvisory[];
  monitoring: {
    id: string;
    enabled: boolean;
    approved_version: string | null;
    latest_seen_version: string | null;
    last_checked_at: string | null;
    consecutive_failures: number;
    project_id: string | null;
  }[];
  release_diffs: {
    id: string;
    old_version: string;
    new_version: string;
    drift_detected: boolean;
    drift_score: number;
    created_at: string;
  }[];
}

// ---------------------------------------------------------------------------------------------
// Dependency graph (SPEC section 10; backend graph/engine.py)
// ---------------------------------------------------------------------------------------------

export type GraphNodeType = "project" | "package" | "vulnerability";
export type GraphEdgeType = "depends_on" | "vulnerable_to";

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  name: string;
  version: string | null;
  direct: boolean;
  depth: number | null;
  risk: number | null;
  severity: Severity | null;
  decision: Decision | null;
  dependents: number;
  transitive_dependents: number;
  transitive_dependencies: number;
  /** 0-1: fraction of non-root packages that transitively depend on this node. */
  blast_radius: number | null;
  direct_exposure: number | null;
  dominated: number | null;
  betweenness: number | null;
  is_single_point: boolean;
  vulnerability_ids: string[];
  findings_count: number | null;
  subtree_max_risk: number | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: GraphEdgeType;
  specifier: string | null;
}

export interface GraphMetrics {
  node_count: number;
  edge_count: number;
  max_depth: number;
  direct_count: number;
  transitive_count: number;
  has_cycles: boolean;
  truncated?: boolean;
  single_points: Record<string, unknown>[];
  high_risk_transitive: Record<string, unknown>[];
  [key: string]: unknown;
}

export interface GraphAnalysis {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metrics: GraphMetrics;
}

// ---------------------------------------------------------------------------------------------
// Events (SPEC section 7)
// ---------------------------------------------------------------------------------------------

/** GET /events item and POST /events/{id}/ack response (backend `schemas/event.py` EventOut). */
export interface SecurityEvent {
  /** UUID. */
  id: string;
  /** One of EVENT_TYPES; typed as string (as in the schema) so a future type does not break parsing. */
  type: string;
  /**
   * The schema types this as a plain string. The event bus only writes SEVERITIES values
   * (`events/types.py` coerce_severity), but views must still guard it (lib/risk isSeverity).
   */
  severity: string;
  /** Attacker-influenced (package names); sanitised and capped at 200 characters by the server. */
  title: string;
  /** PEP 503-normalised package name, when the event concerns one. */
  package: string | null;
  version: string | null;
  project_id: string | null;
  scan_id: string | null;
  /** Sanitised by the server (`sanitize_evidence`); {} when none were recorded. Render as text only. */
  details: Record<string, unknown>;
  created_at: string;
  acknowledged: boolean;
  /** UUID of the acknowledging user. */
  acknowledged_by: string | null;
  acknowledged_at: string | null;
}

/** GET /events query. Results are newest first; limit is 1-200 (default 50), offset 0-1,000,000. */
export interface ListEventsParams extends PageParams {
  /** Sent as `type`; the server also accepts the upper-case member name. */
  type?: EventType;
  severity?: Severity;
  /** Exact package name (normalised by the server before matching), at most 214 characters. */
  package?: string;
  /** UUID. */
  project_id?: string;
  /** ISO 8601 date-time: events created at or after it. */
  since?: string;
  acknowledged?: boolean;
}

// ---------------------------------------------------------------------------------------------
// Projects and SBOM (SPEC sections 5, 9 and 13)
// ---------------------------------------------------------------------------------------------

export interface Project {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface ProjectCreate {
  name: string;
  description?: string | null;
}

/** Row of GET /projects/{id}/scans. */
export interface ProjectScanSummary {
  id: string;
  project_id: string;
  created_at: string;
  component_count: number;
  direct_count: number;
  decision: string | null;
  risk_score: number;
  environment: string | null;
}

export interface ProjectScan extends ProjectScanSummary {
  manifests: { file: string; type: string; sha256?: string }[] | null;
  summary: {
    findings?: Finding[];
    graph_metrics?: Partial<GraphMetrics>;
    warnings?: string[];
    components_with_verdict?: number;
  } | null;
  policy_reasons: { code: string; severity: string; message: string }[] | null;
}

export interface ProjectComponent {
  bom_ref: string;
  name: string;
  version: string | null;
  purl: string | null;
  direct: boolean;
  depth: number | null;
  scope: string | null;
  resolution: string | null;
  declared_at: { file: string; line: number | null }[] | null;
  introduced_by: string[] | null;
  scan_id: string | null;
  risk_score: number | null;
  decision: string | null;
  vulnerability_count: number;
}

/** Manifest files by relative path -> text content. Contents only; the server caps sizes. */
export interface ProjectScanCreate {
  files: Record<string, string>;
  environment?: string;
}

export interface MonitoredPackage {
  id: string;
  ecosystem: string;
  name: string;
  approved_version: string | null;
  latest_seen_version: string | null;
  enabled: boolean;
  poll_interval_seconds: number;
  last_checked_at: string | null;
  next_check_at: string | null;
  last_risk_score: number | null;
  snapshot: { version?: string; risk_score?: number; severity?: string; capabilities?: string[] } | null;
  project_id: string | null;
  consecutive_failures: number;
  created_at: string;
}

export interface MonitoredPackageCreate {
  ecosystem?: "pypi";
  name: string;
  approved_version?: string | null;
  poll_interval_seconds?: number;
  project_id?: string | null;
}

export interface MonitoredPackageUpdate {
  enabled?: boolean;
  approved_version?: string | null;
  poll_interval_seconds?: number;
}

/** POST /monitoring/packages/{id}/check. status: baseline | unchanged | new_release | error. */
export interface MonitoringCheckResult {
  package: string;
  status: string;
  version: string | null;
  diff_id: string | null;
  detail: string | null;
}

/** A finding as listed in a release diff (backend analysis/diff.py). */
export interface DiffFinding {
  code: string;
  severity: string;
  file: string | null;
  line: number | null;
  message: string;
  previous_severity?: string;
}

export interface ReleaseDiffSummary {
  ecosystem: string;
  name: string;
  from_version: string;
  to_version: string;
  /** escalated | reduced | unchanged */
  verdict: string;
  reasons: string[];
  risk: {
    from: number;
    to: number;
    delta: number;
    from_severity: string;
    to_severity: string;
    dimensions: Record<string, { from: number | null; to: number | null; delta: number | null }>;
  };
  capabilities: { added: string[]; removed: string[] };
  files:
    | { available: false; reason: string }
    | {
        available: true;
        added: string[];
        removed: string[];
        changed: string[];
        added_count: number;
        removed_count: number;
        changed_count: number;
        new_executable_binaries: string[];
        install_time_changes: string[];
      };
  maintainers: { available: boolean; added?: string[]; removed?: string[] };
}

export interface ReleaseDiffListItem {
  id: string;
  ecosystem: string;
  package: string;
  old_version: string;
  new_version: string;
  analyzer_version: string;
  drift_detected: boolean;
  drift_score: number;
  created_at: string;
}

export interface ReleaseDiff extends ReleaseDiffListItem {
  summary: ReleaseDiffSummary | null;
  /** Findings that are new in the newer release. */
  findings: DiffFinding[] | null;
}

export interface ReleaseDiffCreate {
  ecosystem?: "pypi";
  name: string;
  from_version: string;
  to_version: string;
}

/** Availability of an analyzer's backing tool or data source (backend analyzers/base.py). */
export interface ToolStatus {
  name: string;
  available: boolean;
  version: string | null;
  detail: string | null;
}

/** Outcome of the optional Trivy pass; status: ok | unavailable | error | timeout | skipped. */
export interface VulnerabilityScanStatus {
  name: string;
  status: string;
  version: string | null;
  detail: string | null;
  vulnerabilities: number;
  truncated: boolean;
}

export interface ContainerScanListItem {
  id: string;
  image_ref: string;
  image_digest: string | null;
  created_at: string;
  /** completed | incomplete */
  status: string;
  decision: string | null;
  risk_score: number | null;
}

export interface ContainerScan extends ContainerScanListItem {
  tools: { trivy?: VulnerabilityScanStatus } | null;
  summary: {
    image_refs?: string[];
    config_digest?: string | null;
    architecture?: string | null;
    os?: string | null;
    user?: string | null;
    exposed_ports?: string[];
    layer_count?: number;
    complete?: boolean;
    component_counts?: Record<string, number>;
    warnings?: string[];
    reasons?: string[];
    finding_counts?: Record<string, number>;
  } | null;
  findings: Finding[] | null;
}

// ---------------------------------------------------------------------------------------------
// Audit, system and ML (SPEC sections 5 and 13)
// ---------------------------------------------------------------------------------------------

/** GET /audit item (backend `schemas/audit.py` AuditEventOut; `metadata_` is serialised as `metadata`). */
export interface AuditEvent {
  /** UUID. */
  id: string;
  /** UUID of the acting user; null for actions without a signed-in actor (e.g. failed logins). */
  actor_id: string | null;
  /** Dotted action name such as "policy.update" (at most 80 characters). */
  action: string;
  target_type: string | null;
  /** Can hold attacker-influenced text (for scan.create: "package==version"). */
  target_id: string | null;
  /** Sanitised by the server; {} when none were recorded. Render as text only. */
  metadata: Record<string, unknown>;
  request_id: string | null;
  created_at: string;
  // Hash chain. Always serialised by the server; null only for rows written outside the chain.
  seq: number | null;
  prev_hash: string | null;
  event_hash: string | null;
}

/** GET /audit query. Results are ordered by seq, newest first; limit is 1-200 (default 50). */
export interface ListAuditParams extends PageParams {
  /** Exact action name, at most 80 characters. */
  action?: string;
  /** UUID. */
  actor_id?: string;
  /** Exact target type, at most 40 characters. */
  target_type?: string;
}

/** GET /audit/verify. ok=false identifies the first broken event of the hash chain. */
export interface AuditVerifyResult {
  ok: boolean;
  /** Events verified before the first break (all events when ok). */
  checked: number;
  /** null when ok, and also when the chain is broken without a specific event (unchained rows). */
  first_broken_seq: number | null;
  reason: string | null;
  /** Last verified event; anchor it outside the database to detect truncation. */
  head_seq: number | null;
  head_hash: string | null;
  verified_at: string;
}

/** GET /system/info `features` (backend api/routers/system.py `system_info`). */
export interface SystemFeatures {
  intel: { enabled: boolean; offline: boolean; nvd_enabled: boolean };
  provenance: boolean;
  monitoring: boolean;
  sandbox: boolean;
  /** token_required is true when METRICS_TOKEN is set (the token itself is never reported). */
  metrics: { enabled: boolean; token_required: boolean };
  /** active: tracing is enabled and the OpenTelemetry API could be loaded. */
  tracing: { enabled: boolean; active: boolean };
  analyze_wheels: boolean;
  sbom_resolve_transitive: boolean;
  /** Configuration switches only; whether each tool is installed is reported by GET /system/tools. */
  external_tools_enabled: { yara: boolean; semgrep: boolean; gitleaks: boolean };
}

/** GET /system/info `limits`: byte sizes, counts, per-minute rates and seconds. */
export interface SystemLimits {
  max_request_body_bytes: number;
  rate_limit_per_minute: number;
  auth_rate_limit_per_minute: number;
  max_download_bytes: number;
  max_extracted_bytes: number;
  max_extracted_files: number;
  max_analyzed_file_bytes: number;
  max_metadata_bytes: number;
  max_manifest_bytes: number;
  max_project_components: number;
  max_graph_nodes: number;
  scan_timeout_seconds: number;
  analyzer_timeout_seconds: number;
  analyzer_workers: number;
  tool_timeout_seconds: number;
}

export interface SystemRuntime {
  /** "redis", or "in_process" when the server fell back to per-process caches and rate limits. */
  cache_backend: string;
  trusted_proxies_configured: boolean;
}

/**
 * GET /system/info (system:read): versions, feature switches and enforced limits. The server never
 * includes secrets, connection strings or filesystem paths. A server of another version can differ,
 * so views read this through runtime guards (features/system/systemInfo.ts).
 */
export interface SystemInfo {
  name: string;
  version: string;
  /** development | staging | production | test */
  env: string;
  analyzer_version: string;
  features: SystemFeatures;
  limits: SystemLimits;
  runtime: SystemRuntime;
}

export interface ModelInfo {
  available: boolean;
  version?: string | null;
  trained_at?: string | null;
  feature_set_version?: string | null;
  algorithm?: string | null;
  metrics?: Record<string, number>;
  [key: string]: unknown;
}

export interface ModelDrift {
  status?: string;
  window?: string | null;
  features?: { name: string; score: number; drifted?: boolean }[];
  [key: string]: unknown;
}

export interface VulnerabilityListItem {
  id: string;
  severity: string;
  cvss_score: number | null;
  kev: boolean;
  epss_score: number | null;
  fixed_versions: string[];
  affected: { package: string; version: string }[];
}

export interface VulnerabilityList {
  total: number;
  items: VulnerabilityListItem[];
}

export interface VulnerabilityListQuery {
  kev?: boolean;
  min_severity?: "unknown" | "low" | "medium" | "high" | "critical";
  limit?: number;
}
