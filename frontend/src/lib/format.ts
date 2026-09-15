const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});

/** Locale date-time, or the raw input when it is not a parseable date. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : dateTimeFormat.format(d);
}

const compactFormat = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const integerFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });

/** 1,284 below ten thousand; 12.9K / 4.2M above. */
export function formatCount(value: number): string {
  if (!Number.isFinite(value)) return "0";
  return Math.abs(value) < 10_000 ? integerFormat.format(value) : compactFormat.format(value);
}

/** 0.923 -> "92%". Values outside 0-1 are clamped. */
export function formatPercent(fraction: number): string {
  if (!Number.isFinite(fraction)) return "0%";
  return `${Math.round(Math.min(1, Math.max(0, fraction)) * 100)}%`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "Not recorded";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

/** "blast_radius" -> "Blast radius". */
export function humanize(identifier: string): string {
  const spaced = identifier.replace(/[_-]+/g, " ").trim();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : identifier;
}
