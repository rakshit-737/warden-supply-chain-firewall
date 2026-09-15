import type { ReactNode } from "react";
import { formatCount } from "../lib/format";

export interface StatDelta {
  /** Signed change against `period`. */
  value: number;
  /** The comparison period, e.g. "previous 30 days". */
  period: string;
  /** Which direction is an improvement. Omit when neither is. */
  better?: "up" | "down";
  format?: (value: number) => string;
}

export interface StatTileProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  delta?: StatDelta;
  /** Slot for a small trend graphic such as <Sparkline />. */
  sparkline?: ReactNode;
}

function formatSigned(value: number): string {
  return `${value > 0 ? "+" : ""}${formatCount(value)}`;
}

function DeltaLine({ delta }: { delta: StatDelta }) {
  const { value, period, better, format = formatSigned } = delta;
  const direction = value > 0 ? "up" : value < 0 ? "down" : "flat";
  const trend = direction === "flat" || !better ? "neutral" : direction === better ? "better" : "worse";
  const glyphFill =
    trend === "better" ? "fill-verdict-allow" : trend === "worse" ? "fill-sev-critical" : "fill-ink-muted";
  return (
    <div data-trend={trend} className="flex items-center gap-1 text-xs text-ink-secondary">
      <svg aria-hidden="true" viewBox="0 0 8 8" className={`h-2 w-2 ${glyphFill}`}>
        {direction === "up" && <path d="M4 1 7.5 7h-7Z" />}
        {direction === "down" && <path d="M4 7 .5 1h7Z" />}
        {direction === "flat" && <rect x="1" y="3.25" width="6" height="1.5" />}
      </svg>
      <span className="tabular-nums text-ink">{format(value)}</span> <span>vs {period}</span>
      {trend !== "neutral" && <span className="sr-only">({trend === "better" ? "an improvement" : "a deterioration"})</span>}
    </div>
  );
}

/** One headline number with an optional change and trend. Numbers are compacted (12.9K). */
export function StatTile({ label, value, hint, delta, sparkline }: StatTileProps) {
  return (
    <div className="flex min-w-0 flex-col gap-1 rounded-md border border-line bg-panel px-4 py-3">
      <div className="text-xs text-ink-secondary">{label}</div>
      <div className="flex items-end justify-between gap-3">
        <div className="min-w-0 font-condensed text-[1.75rem] font-semibold leading-none text-ink">
          {typeof value === "number" ? formatCount(value) : value}
        </div>
        {sparkline && (
          <div aria-hidden="true" className="h-8 w-24 shrink-0">
            {sparkline}
          </div>
        )}
      </div>
      {delta && <DeltaLine delta={delta} />}
      {hint && <div className="text-xs text-ink-muted">{hint}</div>}
    </div>
  );
}

/** Minimal trend line for the StatTile slot. Needs at least two finite values. */
export function Sparkline({ values }: { values: readonly number[] }) {
  const points = values.filter((v) => Number.isFinite(v));
  if (points.length < 2) return null;
  const min = Math.min(...points);
  const span = Math.max(...points) - min || 1;
  const path = points.map((v, i) => `${(i / (points.length - 1)) * 100},${27 - ((v - min) / span) * 24}`).join(" ");
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="h-full w-full">
      <polyline
        points={path}
        fill="none"
        className="stroke-ink-muted"
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
