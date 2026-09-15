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

export interface User {
  id: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  /** Effective permissions computed by a Warden X server (informational; absent on v1). */
  permissions?: string[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserUpdate {
  role?: UserRole;
  is_active?: boolean;
}

export interface ListUsersParams extends PageParams {
  role?: UserRole;
  is_active?: boolean;
  /** Case-insensitive email substring. */
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

/** "expired" is reported by the server for a pending/approved exception past expires_at. */
export const EXCEPTION_STATUSES = ["pending", "approved", "rejected", "revoked", "expired"] as const;
export type ExceptionStatus = (typeof EXCEPTION_STATUSES)[number];

export interface PolicyException {
  id: string;
  /** null = global exception (applies to every policy). */
  policy_id: string | null;
  package: string;
  version_spec: string | null;
  codes: string[];
  categories: string[];
  environment: string | null;
  justification: string;
  requested_by: string;
  /** Who approved or rejected the request. */
  approved_by: string | null;
  revoked_by?: string | null;
  status: ExceptionStatus;
  /** True only when approved and not expired. */
  active?: boolean;
  expires_at: string;
  created_at: string;
  decided_at: string | null;
  revoked_at?: string | null;
}

/** Optional body for approve / reject / revoke. */
export interface ExceptionTransition {
  comment?: string | null;
}

export interface PolicyExceptionCreate {
  package: string;
  version_spec?: string | null;
  codes?: string[];
  categories?: string[];
  environment?: string | null;
  policy_id?: string | null;
  justification: string;
  expires_at: string;
}

export interface ListExceptionsParams extends PageParams {
  status?: ExceptionStatus;
  package?: string;
  policy_id?: string;
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

export interface PackageVersionSummary {
  version: string;
  scan_id: string;
  risk_score: number;
  severity: Severity;
  decision: Decision;
  created_at: string;
}

export interface PackageOverview {
  ecosystem: string;
  name: string;
  versions: PackageVersionSummary[];
  risk_history: { version: string; risk_score: number; created_at: string }[];
  events: SecurityEvent[];
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

export interface SecurityEvent {
  id: string;
  /** One of EVENT_TYPES; typed as string so an unknown future type does not break parsing. */
  type: string;
  severity: Severity;
  title: string;
  package: string | null;
  version: string | null;
  project_id: string | null;
  scan_id: string | null;
  details: Record<string, unknown>;
  created_at: string;
  acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
}

export interface ListEventsParams extends PageParams {
  type?: EventType;
  severity?: Severity;
  package?: string;
  project_id?: string;
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
  created_by: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface ProjectCreate {
  name: string;
  description?: string | null;
}

export interface ProjectManifest {
  file: string;
  type: string;
  sha256: string;
}

export interface ProjectScan {
  id: string;
  project_id: string;
  requested_by: string | null;
  created_at: string;
  manifests: ProjectManifest[];
  component_count: number;
  direct_count: number;
  decision: Decision | null;
  risk_score: number | null;
  summary: Record<string, unknown>;
  policy_reasons: PolicyDecisionReason[];
  environment: string | null;
}

export type ComponentResolution = "pinned" | "locked" | "resolved" | "unresolved";

export interface ProjectComponent {
  id: string;
  project_scan_id: string;
  bom_ref: string;
  name: string;
  version: string | null;
  purl: string | null;
  direct: boolean;
  depth: number | null;
  scope: string;
  resolution: ComponentResolution;
  hashes: Record<string, string[] | string>;
  licenses: string[];
  declared_at: { file: string; line: number | null }[];
  introduced_by: string[];
  scan_id: string | null;
  risk_score: number | null;
  decision: Decision | null;
  vulnerability_count: number;
}

/** Manifest files by name -> text content. Contents only; the server caps sizes. */
export interface ProjectScanCreate {
  files: Record<string, string>;
  environment?: string;
}

// ---------------------------------------------------------------------------------------------
// Monitoring, release diffs and containers (SPEC sections 5 and 13)
// ---------------------------------------------------------------------------------------------

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
  last_scan_id: string | null;
  last_risk_score: number | null;
  snapshot: Record<string, unknown> | null;
  project_id: string | null;
  created_by: string | null;
  created_at: string;
  consecutive_failures: number;
}

export interface MonitoredPackageCreate {
  ecosystem?: "pypi";
  name: string;
  approved_version?: string | null;
  poll_interval_seconds?: number;
  project_id?: string | null;
}

export interface MonitoringStatus {
  enabled?: boolean;
  monitored_count?: number;
  due_count?: number;
  last_run_at?: string | null;
  [key: string]: unknown;
}

export interface ReleaseDiff {
  id: string;
  ecosystem: string;
  package: string;
  old_version: string;
  new_version: string;
  drift_detected: boolean;
  drift_score: number;
  summary: Record<string, unknown>;
  findings: Finding[];
  created_by: string | null;
  created_at: string;
}

export interface ReleaseDiffCreate {
  ecosystem: "pypi";
  name: string;
  old_version: string;
  new_version: string;
}

/** Availability of an analyzer's backing tool or data source (backend analyzers/base.py). */
export interface ToolStatus {
  name: string;
  available: boolean;
  version: string | null;
  detail: string | null;
}

/**
 * Expected values: queued, running, succeeded, failed. Typed as plain string so a status added by
 * a newer server does not break parsing.
 */
export type ContainerScanStatus = string;

export interface ContainerScan {
  id: string;
  image_ref: string;
  image_digest: string | null;
  requested_by: string | null;
  created_at: string;
  status: ContainerScanStatus;
  tools: ToolStatus[];
  summary: Record<string, unknown>;
  findings: Finding[];
  sbom: Record<string, unknown> | null;
  decision: Decision | null;
  risk_score: number | null;
}

/** Exactly one of image_ref / dockerfile / compose is expected by the server. */
export type ContainerScanCreate =
  | { image_ref: string; dockerfile?: never; compose?: never }
  | { dockerfile: string; image_ref?: never; compose?: never }
  | { compose: string; image_ref?: never; dockerfile?: never };

// ---------------------------------------------------------------------------------------------
// Audit, system and ML (SPEC sections 5 and 13)
// ---------------------------------------------------------------------------------------------

export interface AuditEvent {
  id: string;
  actor_id: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  metadata: Record<string, unknown>;
  request_id: string | null;
  created_at: string;
  // Warden X hash chain (optional for v1 backends).
  seq?: number | null;
  prev_hash?: string | null;
  event_hash?: string | null;
}

export interface ListAuditParams extends PageParams {
  action?: string;
  actor_id?: string;
  target_type?: string;
}

/** GET /audit/verify. ok=false identifies the first broken event of the hash chain. */
export interface AuditVerifyResult {
  ok: boolean;
  checked: number;
  first_broken_seq: number | null;
  reason: string | null;
  /** Last verified event; anchor it outside the database to detect truncation. */
  head_seq: number | null;
  head_hash: string | null;
  verified_at: string;
}

/**
 * GET /system/info: versions, feature switches and enforced limits only (the server does not
 * include secrets or connection strings). Every field is optional because the object grows with
 * the deployment's features.
 */
export interface SystemInfo {
  name?: string;
  version?: string;
  /** Deployment environment name, e.g. "production". */
  env?: string;
  analyzer_version?: string;
  features?: Record<string, unknown>;
  limits?: Record<string, number>;
  runtime?: Record<string, unknown>;
  [key: string]: unknown;
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

export interface VulnerabilityQuery {
  package: string;
  version?: string;
}
