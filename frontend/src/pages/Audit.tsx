import { useId, useRef, useState } from "react";
import { listAuditEvents } from "../api/audit";
import type { AuditEvent } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { useAuth } from "../auth/useAuth";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { AuditDetailDrawer } from "../features/audit/AuditDetailDrawer";
import { AuditFilterBar } from "../features/audit/AuditFilterBar";
import {
  AUDIT_FILTER_LABEL,
  hasActiveAuditFilters,
  readAuditQuery,
  shortId,
  toListAuditParams,
} from "../features/audit/auditFilters";
import { VerifyIntegrityPanel } from "../features/audit/VerifyIntegrityPanel";
import { InvalidParamsNotice } from "../features/events/InvalidParamsNotice";
import { RelativeTime } from "../features/events/RelativeTime";
import { usePastEndRedirect, useSearchParamUpdater } from "../features/events/searchParams";
import { useNow } from "../features/events/useNow";
import { useApiQuery } from "../hooks/useApiQuery";
import { revealInvisible } from "../lib/text";
import { numberOrNull } from "../lib/values";

const PAGE_SIZE = 25;

function Actor({ actorId, currentUserId }: { actorId: string | null; currentUserId: string | null }) {
  if (actorId === null) return <span className="text-ink-muted">No signed-in user</span>;
  if (actorId === currentUserId) return <span className="text-ink">You</span>;
  return (
    <code className="font-mono text-xs text-ink" title={actorId}>
      {shortId(actorId)}
    </code>
  );
}

function AuditView() {
  const { user } = useAuth();
  const currentUserId = user?.id ?? null;
  const logHeadingId = useId();
  const [searchParams, updateParams] = useSearchParamUpdater();
  const { filters, offset, ignored } = readAuditQuery(searchParams);
  const params = toListAuditParams(filters, offset, PAGE_SIZE);
  const query = useApiQuery(`audit:${JSON.stringify(params)}`, (signal) => listAuditEvents(params, { signal }));
  const page = query.data ?? query.previousData;
  const now = useNow(30_000);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const tableRegionRef = useRef<HTMLDivElement>(null);
  const pastEnd = usePastEndRedirect(query.data, offset, PAGE_SIZE, updateParams);
  const active = hasActiveAuditFilters(filters);
  const refreshing = query.loading && query.data !== undefined;

  const columns: Column<AuditEvent>[] = [
    {
      id: "seq",
      header: "Seq",
      align: "right",
      cell: (entry) => numberOrNull(entry.seq) ?? <span className="text-ink-muted">None</span>,
    },
    { id: "recorded", header: "Recorded", cell: (entry) => <RelativeTime value={entry.created_at} now={now} /> },
    {
      id: "action",
      header: "Action",
      cell: (entry) => (
        <button
          type="button"
          aria-haspopup="dialog"
          className="break-all text-left font-mono text-[0.8125rem] text-ink hover:text-accent hover:underline"
          onClick={() => setSelected(entry)}
        >
          {revealInvisible(entry.action)} <span className="sr-only">(details of seq {numberOrNull(entry.seq) ?? "not recorded"})</span>
        </button>
      ),
    },
    { id: "actor", header: "Actor", cell: (entry) => <Actor actorId={entry.actor_id} currentUserId={currentUserId} /> },
    {
      id: "target",
      header: "Target",
      cell: (entry) =>
        entry.target_type || entry.target_id ? (
          <div className="flex min-w-0 max-w-xs flex-col">
            <span className="text-xs text-ink-secondary">{entry.target_type ? revealInvisible(entry.target_type) : "No type"}</span>
            {entry.target_id && <code className="break-all font-mono text-xs text-ink">{revealInvisible(entry.target_id)}</code>}
          </div>
        ) : (
          <span className="text-ink-muted">None</span>
        ),
    },
    {
      id: "request",
      header: "Request ID",
      cell: (entry) =>
        entry.request_id ? (
          <code className="font-mono text-xs text-ink-secondary" title={entry.request_id}>
            {revealInvisible(shortId(entry.request_id, 12))}
          </code>
        ) : (
          <span className="text-ink-muted">None</span>
        ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Audit"
        description="The append-only audit trail of security-relevant actions, newest first, and verification of its hash chain."
        actions={
          <button
            type="button"
            className="btn-secondary"
            aria-disabled={refreshing || undefined}
            onClick={() => {
              if (!refreshing) query.reload();
            }}
          >
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />
      <div className="flex flex-col gap-5">
        <VerifyIntegrityPanel now={now} />

        <section aria-labelledby={logHeadingId} className="min-w-0">
          <h2 id={logHeadingId} className="mb-2 text-[0.9375rem] font-semibold text-ink">
            Audit log
          </h2>
          <InvalidParamsNotice
            labels={ignored.map((name) => AUDIT_FILTER_LABEL[name])}
            onRemove={() => updateParams(Object.fromEntries(ignored.map((name) => [name, null])))}
          />
          <AuditFilterBar filters={filters} currentUserId={currentUserId} onChange={updateParams} />
          <Card flush>
            <div ref={tableRegionRef} tabIndex={-1} className="focus:outline-hidden">
              <DataTable
                caption="Audit log"
                columns={columns}
                rows={page?.items}
                rowKey={(entry) => entry.id}
                loading={query.loading && query.data === undefined}
                error={query.error}
                onRetry={query.reload}
                empty={
                  pastEnd ? (
                    <EmptyState
                      compact
                      title="This page is past the end of the log."
                      action={
                        <button type="button" className="btn-secondary" onClick={() => updateParams({ offset: null })}>
                          Go to the first page
                        </button>
                      }
                    />
                  ) : (
                    <EmptyState
                      compact
                      title={active ? "No audit entries match these filters." : "No audit entries recorded yet."}
                      description={active ? "Change or clear the filters. Action and target type must match exactly." : undefined}
                    />
                  )
                }
                pagination={
                  page && page.total > 0
                    ? {
                        total: page.total,
                        limit: page.limit || PAGE_SIZE,
                        offset: page.offset,
                        onOffsetChange: (next) => updateParams({ offset: next > 0 ? String(next) : null }),
                      }
                    : undefined
                }
                footnote="Ordered by sequence number, newest first."
              />
            </div>
          </Card>
        </section>
      </div>

      <AuditDetailDrawer
        entry={selected}
        now={now}
        currentUserId={currentUserId}
        onFilter={(changes) => {
          setSelected(null);
          updateParams(changes);
        }}
        onClose={() => setSelected(null)}
        fallbackFocus={() => tableRegionRef.current}
      />
    </>
  );
}

/** The audit trail and hash-chain verification (audit:read: admin and auditor). */
export default function Audit() {
  return (
    <RequirePermission permission={PERMISSIONS.AUDIT_READ}>
      <AuditView />
    </RequirePermission>
  );
}
