import {
  DECISIONS,
  RISK_DIMENSIONS,
  SEVERITIES,
  type Decision,
  type RiskDimension,
  type Severity,
} from "../api/types";

/**
 * Risk score bands (SPEC section 4): >=80 critical, >=60 high, >=35 medium, >=15 low, else info.
 * `min` is inclusive, `max` exclusive (except the last band, which includes 100).
 */
export const RISK_BANDS: readonly { severity: Severity; min: number; max: number }[] = [
  { severity: "info", min: 0, max: 15 },
  { severity: "low", min: 15, max: 35 },
  { severity: "medium", min: 35, max: 60 },
  { severity: "high", min: 60, max: 80 },
  { severity: "critical", min: 80, max: 100 },
];

/** Lower bounds of the low, medium, high and critical bands. */
export const RISK_THRESHOLDS = [15, 35, 60, 80] as const;

export const SEVERITY_LABEL: Record<Severity, string> = {
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export const DECISION_LABEL: Record<Decision, string> = {
  allow: "Allow",
  warn: "Warn",
  block: "Block",
};

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Clamp to an integer 0-100. Non-finite input becomes 0. */
export function clampScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.round(Math.min(100, Math.max(0, value)));
}

export function severityForScore(score: number): Severity {
  const s = clampScore(score);
  if (s >= 80) return "critical";
  if (s >= 60) return "high";
  if (s >= 35) return "medium";
  if (s >= 15) return "low";
  return "info";
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

export function isDecision(value: unknown): value is Decision {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

/** Rank for sorting; unknown values sort below info. */
export function severityRank(value: unknown): number {
  return isSeverity(value) ? SEVERITY_RANK[value] : -1;
}

/** 1 (info) to 5 (critical). */
export function severityLevel(severity: Severity): number {
  return SEVERITY_RANK[severity] + 1;
}

export interface RankableFinding {
  severity: string;
  confidence?: number | null;
  weight: number;
  code: string;
}

/** Most important first: severity, then confidence, then weight (mirrors the backend sort_key). */
export function compareFindings(a: RankableFinding, b: RankableFinding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    (b.confidence ?? 0) - (a.confidence ?? 0) ||
    (Number.isFinite(b.weight) ? b.weight : 0) - (Number.isFinite(a.weight) ? a.weight : 0) ||
    String(a.code).localeCompare(String(b.code))
  );
}

// ---------------------------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------------------------

export type ConfidenceBucket = "deterministic" | "strong" | "heuristic" | "weak";

export const CONFIDENCE_BUCKET_LABEL: Record<ConfidenceBucket, string> = {
  deterministic: "deterministic",
  strong: "strong",
  heuristic: "heuristic",
  weak: "weak",
};

export const CONFIDENCE_BUCKET_STEPS: Record<ConfidenceBucket, number> = {
  weak: 1,
  heuristic: 2,
  strong: 3,
  deterministic: 4,
};

/** 0.923 -> 92. Values are clamped to 0-1; null when not a finite number. */
export function confidencePercent(value: number | null | undefined): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.round(Math.min(1, Math.max(0, value)) * 100);
}

/**
 * Evidence tier for a rounded percentage, following the SPEC confidence guidance: >=95 exact
 * deterministic evidence, >=80 strong structural evidence, >=50 heuristic, below that weak.
 */
export function confidenceBucket(percent: number): ConfidenceBucket {
  if (percent >= 95) return "deterministic";
  if (percent >= 80) return "strong";
  if (percent >= 50) return "heuristic";
  return "weak";
}

// ---------------------------------------------------------------------------------------------
// Risk dimensions
// ---------------------------------------------------------------------------------------------

/** Known dimensions in SPEC order, then any others alphabetically. Non-object entries are dropped. */
export function orderRiskDimensions(dimensions: unknown): { name: string; dimension: RiskDimension }[] {
  if (!dimensions || typeof dimensions !== "object" || Array.isArray(dimensions)) return [];
  const known = RISK_DIMENSIONS as readonly string[];
  const rank = (name: string) => {
    const index = known.indexOf(name);
    return index === -1 ? known.length : index;
  };
  return Object.entries(dimensions)
    .filter((entry): entry is [string, RiskDimension] => typeof entry[1] === "object" && entry[1] !== null)
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([name, dimension]) => ({ name, dimension }));
}
