import { humanize } from "../lib/format";
import { clampScore, orderRiskDimensions, severityForScore } from "../lib/risk";
import { SEVERITY_FILL } from "../theme/classes";
import { ConfidencePill } from "./ConfidencePill";
import { EmptyState } from "./EmptyState";

export interface RiskBreakdownBarsProps {
  /** `risk.dimensions` from a scan: dimension name -> RiskDimension. Malformed entries are skipped. */
  dimensions: unknown;
}

/**
 * One row per risk dimension (Risk Engine 2.0). A null score is shown as "unknown", never as 0:
 * it means the dimension could not be assessed (for example, vulnerability intel was offline).
 */
export function RiskBreakdownBars({ dimensions }: RiskBreakdownBarsProps) {
  const rows = orderRiskDimensions(dimensions);
  if (rows.length === 0) return <EmptyState compact title="No risk dimensions were recorded." />;
  return (
    <ul aria-label="Risk dimensions" className="divide-y divide-line">
      {rows.map(({ name, dimension }) => {
        const score =
          typeof dimension.score === "number" && Number.isFinite(dimension.score) ? clampScore(dimension.score) : null;
        return (
          <li
            key={name}
            data-dimension={name}
            className="grid grid-cols-1 gap-x-4 gap-y-1 py-2.5 sm:grid-cols-[9rem_minmax(0,1fr)_auto] sm:items-center"
          >
            <span className="font-medium text-ink">{humanize(name)}</span>
            <span className="flex items-center gap-3">
              <span aria-hidden="true" className="relative h-1.5 flex-1 overflow-hidden rounded-full bg-line">
                {score !== null && (
                  <span
                    className={`absolute inset-y-0 left-0 rounded-full ${SEVERITY_FILL[severityForScore(score)]}`}
                    style={{ width: `${score}%` }}
                  />
                )}
              </span>
              <span className={`w-14 text-right tabular-nums ${score === null ? "text-ink-muted" : "text-ink"}`}>
                <span className="sr-only">Score </span>
                {score === null ? "unknown" : score}
              </span>
            </span>
            <span>
              <ConfidencePill value={dimension.confidence} compact />
            </span>
            {dimension.rationale && (
              <p className="wrap-break-word text-xs text-ink-secondary sm:col-span-3">{dimension.rationale}</p>
            )}
          </li>
        );
      })}
    </ul>
  );
}
