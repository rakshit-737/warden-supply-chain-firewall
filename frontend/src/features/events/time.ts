// Timestamps for security events and audit records: a relative phrase for scanning a list
// ("5 minutes ago") next to the exact local time with seconds and time zone.

const RELATIVE_UNITS: readonly (readonly [Intl.RelativeTimeFormatUnit, number])[] = [
  ["year", 365 * 86_400],
  ["month", 30 * 86_400],
  ["week", 7 * 86_400],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];

/** Differences below this many seconds (in either direction, to absorb clock skew) read "just now". */
export const JUST_NOW_SECONDS = 45;

const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

const timestampFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  timeZoneName: "short",
});

/** Epoch milliseconds of a timestamp string, or null when it is missing or does not parse. */
export function parseTimestamp(value: string | null | undefined): number | null {
  if (typeof value !== "string" || value.trim() === "") return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/** "5 minutes ago", "yesterday", "just now"; null when `value` is not a timestamp. */
export function formatRelativeTime(value: string | null | undefined, now: number): string | null {
  const time = parseTimestamp(value);
  if (time === null || !Number.isFinite(now)) return null;
  const seconds = (time - now) / 1000;
  const magnitude = Math.abs(seconds);
  if (magnitude < JUST_NOW_SECONDS) return "just now";
  for (const [unit, size] of RELATIVE_UNITS) {
    if (magnitude >= size) return relativeFormat.format(Math.trunc(seconds / size), unit);
  }
  return relativeFormat.format(Math.trunc(seconds), "second");
}

/** Local date and time with seconds and zone; the raw text when it does not parse. */
export function formatTimestamp(value: string | null | undefined): string {
  if (typeof value !== "string" || value.trim() === "") return "Not recorded";
  const time = parseTimestamp(value);
  return time === null ? value : timestampFormat.format(time);
}

function pad(value: number, length = 2): string {
  return String(value).padStart(length, "0");
}

/** An ISO timestamp as the local "YYYY-MM-DDTHH:mm" value of an <input type="datetime-local">. */
export function toLocalInputValue(value: string | null | undefined): string {
  const time = parseTimestamp(value);
  if (time === null) return "";
  const d = new Date(time);
  return `${pad(d.getFullYear(), 4)}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const LOCAL_INPUT_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/;

/** A datetime-local value (local time) as an ISO 8601 UTC timestamp; null when it is not a real date. */
export function fromLocalInputValue(value: string): string | null {
  const match = LOCAL_INPUT_RE.exec(value.trim());
  if (!match) return null;
  const [year, month, day, hour, minute, second] = match.slice(1).map((part) => Number(part ?? 0)) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const d = new Date(year, month - 1, day, hour, minute, second);
  // new Date() rolls invalid components over (31 April becomes 1 May); reject those instead.
  const valid =
    d.getFullYear() === year &&
    d.getMonth() === month - 1 &&
    d.getDate() === day &&
    d.getHours() === hour &&
    d.getMinutes() === minute;
  return valid && !Number.isNaN(d.getTime()) ? d.toISOString() : null;
}
