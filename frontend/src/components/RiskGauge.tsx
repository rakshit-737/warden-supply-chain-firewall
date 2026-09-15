import { RISK_THRESHOLDS, SEVERITY_LABEL, clampScore, severityForScore } from "../lib/risk";
import { SEVERITY_FILL, SEVERITY_TRACK } from "../theme/classes";

const SIZES = {
  sm: { root: "gap-2", value: "w-7 text-right text-[0.8125rem] tabular-nums", track: "h-1.5 w-16" },
  md: { root: "gap-2.5", value: "w-8 text-right text-sm font-semibold tabular-nums", track: "h-2 w-28" },
  lg: { root: "w-full gap-3", value: "font-condensed text-4xl font-semibold leading-none", track: "h-2.5 min-w-[8rem] flex-1" },
} as const;

export interface RiskGaugeProps {
  /** 0-100; null/undefined means the score was not assessed. */
  score: number | null | undefined;
  /** Accessible name of the meter. */
  label?: string;
  size?: keyof typeof SIZES;
}

/**
 * Linear 0-100 risk meter. The fill takes the colour of the score's band (info < 15 <= low < 35 <=
 * medium < 60 <= high < 80 <= critical) and the band boundaries are drawn as gaps in the track.
 */
export function RiskGauge({ score, label = "Risk score", size = "md" }: RiskGaugeProps) {
  const s = SIZES[size];
  if (typeof score !== "number" || !Number.isFinite(score)) {
    return (
      <span data-band="unknown" className={`inline-flex items-center text-ink-muted ${s.root}`}>
        <span className="sr-only">{label}: </span>Unknown
      </span>
    );
  }
  const value = clampScore(score);
  const band = severityForScore(value);
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      aria-valuetext={`${value} of 100, ${SEVERITY_LABEL[band].toLowerCase()}`}
      data-band={band}
      className={`inline-flex items-center ${s.root}`}
    >
      <span className={`text-ink ${s.value}`}>{value}</span>
      <span className={`relative overflow-hidden rounded-full ${SEVERITY_TRACK[band]} ${s.track}`}>
        <span className={`absolute inset-y-0 left-0 ${SEVERITY_FILL[band]}`} style={{ width: `${value}%` }} />
        {RISK_THRESHOLDS.map((threshold) => (
          <span
            key={threshold}
            className="absolute inset-y-0 w-[2px] -translate-x-1/2 bg-panel"
            style={{ left: `${threshold}%` }}
          />
        ))}
      </span>
      {size !== "sm" && <span className="whitespace-nowrap text-xs text-ink-secondary">{SEVERITY_LABEL[band]}</span>}
    </div>
  );
}
