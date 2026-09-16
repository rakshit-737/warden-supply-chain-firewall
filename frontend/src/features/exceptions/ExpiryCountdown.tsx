import type { PolicyException } from "../../api/types";
import { formatDateTime } from "../../lib/format";
import { EXPIRY_WARNING_MS, effectiveStatus, formatTimeSpan, isOpenStatus } from "./expiry";

export interface ExpiryCountdownProps {
  exception: Pick<PolicyException, "status" | "expires_at">;
  /** Current time in milliseconds (useNow), so the countdown advances without reloading. */
  now: number;
}

/** Time left before an open exception expires, how long ago it expired, or the date it was due to. */
export function ExpiryCountdown({ exception, now }: ExpiryCountdownProps) {
  const expiresAt = Date.parse(exception.expires_at);
  if (Number.isNaN(expiresAt)) return <span className="text-ink-muted">Not recorded</span>;
  const status = effectiveStatus(exception, now);
  const date = (
    <time dateTime={exception.expires_at} className="whitespace-nowrap text-xs text-ink-muted">
      {formatDateTime(exception.expires_at)}
    </time>
  );

  if (status === "expired") {
    return (
      <span className="flex flex-col items-start gap-0.5">
        <span className="whitespace-nowrap text-ink">Expired {formatTimeSpan(now - expiresAt)} ago</span>
        {date}
      </span>
    );
  }
  if (isOpenStatus(status)) {
    const soon = expiresAt - now <= EXPIRY_WARNING_MS;
    return (
      <span className="flex flex-col items-start gap-0.5">
        <span className={`inline-flex items-center gap-1.5 whitespace-nowrap text-ink ${soon ? "font-semibold" : ""}`}>
          {soon && <span aria-hidden="true" className="h-2 w-2 shrink-0 rounded-full bg-sev-medium" />}
          Expires in {formatTimeSpan(expiresAt - now)}
        </span>
        {date}
      </span>
    );
  }
  return (
    <span className="flex flex-col items-start gap-0.5">
      <span className="whitespace-nowrap text-ink-muted">No longer applies</span>
      {date}
    </span>
  );
}
