import { SEVERITY_LABEL, isSeverity, severityLevel } from "../lib/risk";
import { SEVERITY_FILL } from "../theme/classes";

const PIP_HEIGHTS = ["h-1", "h-1.5", "h-2", "h-2.5", "h-3"] as const;

export interface SeverityBadgeProps {
  /** Any value; anything that is not a known severity renders as "Unknown". */
  value: unknown;
  className?: string;
}

/** Severity label plus a five-step pip glyph, so the level reads without relying on colour. */
export function SeverityBadge({ value, className = "" }: SeverityBadgeProps) {
  const severity = isSeverity(value) ? value : null;
  const level = severity ? severityLevel(severity) : 0;
  const mark = severity ? SEVERITY_FILL[severity] : "";
  return (
    <span
      data-severity={severity ?? "unknown"}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-medium text-ink ${className}`}
    >
      <span aria-hidden="true" className="inline-flex h-3 items-end gap-[2px]">
        {PIP_HEIGHTS.map((height, index) => (
          <span key={height} className={`w-[3px] rounded-[1px] ${height} ${index < level ? mark : "bg-line-strong"}`} />
        ))}
      </span>
      {severity ? SEVERITY_LABEL[severity] : "Unknown"}
    </span>
  );
}
