import { CONFIDENCE_BUCKET_LABEL, CONFIDENCE_BUCKET_STEPS, confidenceBucket, confidencePercent } from "../lib/risk";

export interface ConfidencePillProps {
  /** 0.0-1.0. null/undefined renders as unknown. */
  value: number | null | undefined;
  /** Hide the visible "Confidence" word (it stays available to screen readers). */
  compact?: boolean;
}

/** Likelihood that a finding is a true positive: a percentage plus its evidence tier (SPEC section 1). */
export function ConfidencePill({ value, compact = false }: ConfidencePillProps) {
  const percent = confidencePercent(value);
  const bucket = percent === null ? null : confidenceBucket(percent);
  const filled = bucket === null ? 0 : CONFIDENCE_BUCKET_STEPS[bucket];
  return (
    <span
      data-confidence={bucket ?? "unknown"}
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line px-2 py-0.5 text-xs text-ink-secondary"
    >
      <span aria-hidden="true" className="inline-flex gap-[2px]">
        {[1, 2, 3, 4].map((step) => (
          <span key={step} className={`h-1.5 w-1.5 rounded-full ${step <= filled ? "bg-ink-secondary" : "bg-line-strong"}`} />
        ))}
      </span>
      <span className={compact ? "sr-only" : undefined}>Confidence</span>{" "}
      {percent === null || bucket === null ? (
        <span>unknown</span>
      ) : (
        <>
          <span className="tabular-nums text-ink">{percent}%</span> <span>{CONFIDENCE_BUCKET_LABEL[bucket]}</span>
        </>
      )}
    </span>
  );
}
