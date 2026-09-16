import type { ExceptionStatus } from "../../api/types";
import { humanize } from "../../lib/format";

const LABEL: Record<ExceptionStatus, string> = {
  pending: "Pending",
  approved: "Approved",
  rejected: "Rejected",
  revoked: "Revoked",
  expired: "Expired",
};

/** Distinct shapes carry the status without colour: ring, disc, octagon, slashed ring, hourglass. */
function StatusGlyph({ status }: { status: ExceptionStatus }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 12 12" className="h-2.5 w-2.5 shrink-0">
      {status === "pending" && <circle cx="6" cy="6" r="4.25" strokeWidth="1.5" className="fill-none stroke-ink-secondary" />}
      {status === "approved" && <circle cx="6" cy="6" r="5" className="fill-verdict-allow" />}
      {status === "rejected" && <path d="M3.9.8h4.2l3.1 3.1v4.2l-3.1 3.1H3.9L.8 8.1V3.9Z" className="fill-verdict-block" />}
      {status === "revoked" && (
        <>
          <circle cx="6" cy="6" r="4.25" strokeWidth="1.5" className="fill-none stroke-sev-high" />
          <path d="M3 9 9 3" strokeWidth="1.5" className="stroke-sev-high" />
        </>
      )}
      {status === "expired" && <path d="M2 1h8v1.6L7 6l3 3.4V11H2V9.4L5 6 2 2.6Z" className="fill-ink-muted" />}
    </svg>
  );
}

export interface ExceptionStatusBadgeProps {
  /** The effective status (see effectiveStatus): pass "expired" once expires_at has passed. */
  status: ExceptionStatus;
  className?: string;
}

export function ExceptionStatusBadge({ status, className = "" }: ExceptionStatusBadgeProps) {
  const known = Object.prototype.hasOwnProperty.call(LABEL, status);
  return (
    <span
      data-status={status}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded border bg-raised px-1.5 py-0.5 text-xs font-semibold text-ink ${
        status === "expired" ? "border-dashed border-line-strong" : "border-line"
      } ${className}`}
    >
      {known && <StatusGlyph status={status} />}
      {known ? LABEL[status] : humanize(String(status))}
    </span>
  );
}
