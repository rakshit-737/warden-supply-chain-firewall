import { formatRelativeTime, formatTimestamp } from "./time";

export interface RelativeTimeProps {
  /** ISO timestamp from the server. */
  value: string | null | undefined;
  /** Reference time (epoch ms), usually from useNow. */
  now: number;
  /** "stacked" puts the exact time under the relative one; "inline" follows it in parentheses. */
  layout?: "stacked" | "inline";
}

/** Relative time for scanning plus the exact local time, both visible (never only in a tooltip). */
export function RelativeTime({ value, now, layout = "stacked" }: RelativeTimeProps) {
  if (typeof value !== "string" || value.trim() === "") return <span className="text-ink-muted">Not recorded</span>;
  const relative = formatRelativeTime(value, now);
  if (relative === null) return <span className="break-all">{value}</span>;
  const absolute = formatTimestamp(value);
  if (layout === "inline") {
    return (
      <time dateTime={value} className="tabular-nums">
        {relative} <span className="text-ink-secondary">({absolute})</span>
      </time>
    );
  }
  return (
    <time dateTime={value} className="flex flex-col whitespace-nowrap tabular-nums">
      <span className="text-ink">{relative}</span>
      <span className="text-xs text-ink-muted">{absolute}</span>
    </time>
  );
}
