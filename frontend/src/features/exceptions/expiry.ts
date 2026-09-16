import type { ExceptionStatus, PolicyException } from "../../api/types";

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/** Open exceptions can still change: pending ones can be decided, and both can be revoked. */
export function isOpenStatus(status: ExceptionStatus): boolean {
  return status === "pending" || status === "approved";
}

/**
 * Status as of `now`, mirroring the server's `effective_status`: an open exception whose expiry has
 * passed is expired, even if it was pending or approved when the list was loaded.
 */
export function effectiveStatus(exception: Pick<PolicyException, "status" | "expires_at">, now: number): ExceptionStatus {
  const expiresAt = Date.parse(exception.expires_at);
  if (isOpenStatus(exception.status) && !Number.isNaN(expiresAt) && expiresAt <= now) return "expired";
  return exception.status;
}

function plural(count: number, unit: string): string {
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}

/** A duration in the largest whole unit: "3 days", "1 hour", "12 minutes" or "less than a minute". */
export function formatTimeSpan(ms: number): string {
  const span = Math.abs(ms);
  if (span >= DAY_MS) return plural(Math.floor(span / DAY_MS), "day");
  if (span >= HOUR_MS) return plural(Math.floor(span / HOUR_MS), "hour");
  if (span >= MINUTE_MS) return plural(Math.floor(span / MINUTE_MS), "minute");
  return "less than a minute";
}

/** Open exceptions this close to expiry are highlighted. */
export const EXPIRY_WARNING_MS = 7 * DAY_MS;
