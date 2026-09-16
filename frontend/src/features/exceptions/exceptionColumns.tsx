import type { PolicyException } from "../../api/types";
import type { Column } from "../../components/DataTable";
import { formatDateTime, humanize } from "../../lib/format";
import { ExceptionStatusBadge } from "./ExceptionStatusBadge";
import { ExpiryCountdown } from "./ExpiryCountdown";
import { ScopeChips } from "./ScopeChips";
import { effectiveStatus } from "./expiry";

export interface ExceptionColumnOptions {
  now: number;
  currentUserId: string | null;
  selectedId: string | null;
  onSelect: (exception: PolicyException) => void;
}

/** Columns of the exception list. The server orders rows newest first and cannot sort otherwise. */
export function exceptionColumns({ now, currentUserId, selectedId, onSelect }: ExceptionColumnOptions): Column<PolicyException>[] {
  return [
    {
      id: "package",
      header: "Package",
      cell: (exception) => {
        const selected = exception.id === selectedId;
        return (
          <button
            type="button"
            aria-current={selected ? "true" : undefined}
            onClick={() => onSelect(exception)}
            className="flex flex-col items-start text-left text-ink hover:text-accent"
          >
            <span className={`break-all font-mono text-[0.8125rem] hover:underline ${selected ? "font-semibold" : ""}`}>
              {exception.package}
            </span>
            {exception.version_spec && (
              <span className="break-all font-mono text-2xs text-ink-muted">{exception.version_spec}</span>
            )}
          </button>
        );
      },
    },
    {
      id: "scope",
      header: "Scope",
      cell: (exception) => <ScopeChips codes={exception.codes} categories={exception.categories} limit={2} />,
    },
    {
      id: "environment",
      header: "Environment",
      cell: (exception) =>
        exception.environment ? humanize(exception.environment) : <span className="text-ink-muted">Every environment</span>,
    },
    {
      id: "status",
      header: "Status",
      cell: (exception) => <ExceptionStatusBadge status={effectiveStatus(exception, now)} />,
    },
    {
      id: "expires",
      header: "Expiry",
      cell: (exception) => <ExpiryCountdown exception={exception} now={now} />,
    },
    {
      id: "requested",
      header: "Requested",
      cell: (exception) => (
        <span className="flex flex-col items-start">
          <time dateTime={exception.created_at} className="whitespace-nowrap tabular-nums text-ink-secondary">
            {formatDateTime(exception.created_at)}
          </time>
          {exception.requested_by === currentUserId && <span className="text-2xs text-ink-muted">by you</span>}
        </span>
      ),
    },
  ];
}
