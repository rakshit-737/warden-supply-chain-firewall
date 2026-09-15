import type { Decision, Severity } from "../api/types";

// Complete Tailwind class strings (never assembled from fragments) so Tailwind can detect them.

export const SEVERITY_FILL: Record<Severity, string> = {
  info: "bg-sev-info",
  low: "bg-sev-low",
  medium: "bg-sev-medium",
  high: "bg-sev-high",
  critical: "bg-sev-critical",
};

/** A lighter step of the same hue for the unfilled part of a meter. */
export const SEVERITY_TRACK: Record<Severity, string> = {
  info: "bg-sev-info/25",
  low: "bg-sev-low/25",
  medium: "bg-sev-medium/25",
  high: "bg-sev-high/25",
  critical: "bg-sev-critical/25",
};

export const DECISION_FILL: Record<Decision, string> = {
  allow: "bg-verdict-allow",
  warn: "bg-verdict-warn",
  block: "bg-verdict-block",
};

export const DECISION_GLYPH_FILL: Record<Decision, string> = {
  allow: "fill-verdict-allow",
  warn: "fill-verdict-warn",
  block: "fill-verdict-block",
};
