import type { Decision } from "../api/types";
import { DECISION_LABEL, isDecision } from "../lib/risk";
import { DECISION_GLYPH_FILL } from "../theme/classes";

/** Road-sign shapes carry the verdict without colour: circle = allow, triangle = warn, octagon = block. */
function DecisionGlyph({ decision, className }: { decision: Decision | null; className: string }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 12 12"
      className={`shrink-0 ${className} ${decision ? DECISION_GLYPH_FILL[decision] : "fill-ink-muted"}`}
    >
      {decision === "allow" && <circle cx="6" cy="6" r="5" />}
      {decision === "warn" && <path d="M6 .9 11.4 10.6H.6Z" />}
      {decision === "block" && <path d="M3.9.8h4.2l3.1 3.1v4.2l-3.1 3.1H3.9L.8 8.1V3.9Z" />}
      {decision === null && <rect x="1.5" y="5" width="9" height="2" rx="1" />}
    </svg>
  );
}

export interface DecisionBadgeProps {
  /** Any value; anything that is not allow/warn/block renders as "Unknown". */
  value: unknown;
  /** "lg" is the verdict plate used at the top of a scan. */
  size?: "sm" | "lg";
  className?: string;
}

export function DecisionBadge({ value, size = "sm", className = "" }: DecisionBadgeProps) {
  const decision = isDecision(value) ? value : null;
  const label = decision ? DECISION_LABEL[decision] : "Unknown";
  if (size === "lg") {
    return (
      <span data-decision={decision ?? "unknown"} className={`inline-flex items-center gap-2.5 ${className}`}>
        <DecisionGlyph decision={decision} className="h-7 w-7" />
        <span className="font-condensed text-3xl font-semibold leading-none text-ink">{label}</span>
      </span>
    );
  }
  return (
    <span
      data-decision={decision ?? "unknown"}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border border-line bg-raised px-1.5 py-0.5 text-xs font-semibold text-ink ${className}`}
    >
      <DecisionGlyph decision={decision} className="h-2.5 w-2.5" />
      {label}
    </span>
  );
}
