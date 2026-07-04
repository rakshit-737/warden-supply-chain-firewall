export type Role = "admin" | "analyst" | "viewer";
export type Decision = "allow" | "warn" | "block";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface User {
  id: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export interface Signal {
  code: string;
  severity: Severity;
  weight: number;
  message: string;
  evidence: Record<string, unknown>;
}

export interface Scan {
  id: string;
  ecosystem: string;
  package_name: string;
  version: string;
  rule_score: number;
  ml_score: number;
  risk_score: number;
  severity: Severity;
  decision: Decision;
  matched_policy_rules: string[];
  feature_vector: Record<string, number>;
  analyzer_version: string;
  duration_ms: number;
  created_at: string;
  signals: Signal[];
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
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScanStats {
  total: number;
  by_decision: Record<Decision, number>;
  by_severity: Record<Severity, number>;
  blocked_last_30d: number;
  avg_risk_score: number;
  top_signals: { code: string; count: number }[];
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
}
