import { useRef, useState } from "react";
import { Link } from "react-router";
import { listEvents } from "../api/events";
import type { SecurityEvent } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { useAuth } from "../auth/useAuth";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { SeverityBadge } from "../components/SeverityBadge";
import { AckControl } from "../features/events/AckControl";
import { AutoRefreshControl } from "../features/events/AutoRefreshControl";
import { InvalidParamsNotice } from "../features/events/InvalidParamsNotice";
import { EventDetailDrawer } from "../features/events/EventDetailDrawer";
import { EventFilterBar } from "../features/events/EventFilterBar";
import {
  EVENT_FILTER_LABEL,
  hasActiveEventFilters,
  readEventQuery,
  toListEventsParams,
} from "../features/events/eventFilters";
import { eventTypeLabel, scanPath } from "../features/events/eventLabels";
import { RelativeTime } from "../features/events/RelativeTime";
import { usePastEndRedirect, useSearchParamUpdater } from "../features/events/searchParams";
import { useAcknowledgements } from "../features/events/useAcknowledgements";
import { useAutoRefresh } from "../features/events/useAutoRefresh";
import { useNow } from "../features/events/useNow";
import { useApiQuery } from "../hooks/useApiQuery";
import { revealInvisible } from "../lib/text";

const PAGE_SIZE = 25;
const EVENTS_REFRESH_INTERVAL_MS = 30_000;
const AUTO_REFRESH_STORAGE_KEY = "warden.events.auto-refresh";

function readAutoRefreshPreference(): boolean {
  try {
    return window.localStorage.getItem(AUTO_REFRESH_STORAGE_KEY) !== "off";
  } catch {
    return true;
  }
}

function storeAutoRefreshPreference(enabled: boolean): void {
  try {
    window.localStorage.setItem(AUTO_REFRESH_STORAGE_KEY, enabled ? "on" : "off");
  } catch {
    // Storage can be unavailable (private browsing, site-data policy); the choice then lasts for this visit.
  }
}

function EventsView() {
  const { user } = useAuth();
  const currentUserId = user?.id ?? null;
  const canAcknowledge = usePermission(PERMISSIONS.EVENT_ACK);
  const [searchParams, updateParams] = useSearchParamUpdater();
  const { filters, offset, ignored } = readEventQuery(searchParams);
  const params = toListEventsParams(filters, offset, PAGE_SIZE);

  const query = useApiQuery(`events:${JSON.stringify(params)}`, (signal) =>
    listEvents(params, { signal }).then((page) => ({ page, fetchedAt: Date.now() })),
  );
  const loaded = query.data ?? query.previousData;
  const page = loaded?.page;
  const now = useNow(15_000);
  const reference = Math.max(now, loaded?.fetchedAt ?? 0);

  const [autoRefresh, setAutoRefresh] = useState(readAutoRefreshPreference);
  const { hidden } = useAutoRefresh({
    enabled: autoRefresh,
    intervalMs: EVENTS_REFRESH_INTERVAL_MS,
    onRefresh: query.reload,
    lastUpdatedAt: query.data?.fetchedAt,
    busy: query.loading,
  });

  const acks = useAcknowledgements(currentUserId);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const tableRegionRef = useRef<HTMLDivElement>(null);
  const pastEnd = usePastEndRedirect(query.data?.page, offset, PAGE_SIZE, updateParams);
  const active = hasActiveEventFilters(filters);

  // The drawer follows the freshest copy of the selected event on this page.
  const selectedEvent = selected ? (page?.items.find((event) => event.id === selected.id) ?? selected) : null;
  const selectedView = selectedEvent ? acks.view(selectedEvent) : null;
  const failure = acks.failure;

  const columns: Column<SecurityEvent>[] = [
    { id: "severity", header: "Severity", cell: (event) => <SeverityBadge value={event.severity} /> },
    {
      id: "event",
      header: "Event",
      cell: (event) => (
        <div className="min-w-[12rem] max-w-md">
          <button
            type="button"
            aria-haspopup="dialog"
            className="break-words text-left font-medium text-ink hover:text-accent hover:underline"
            onClick={() => setSelected(event)}
          >
            {revealInvisible(event.title)}
          </button>
          <div className="text-xs text-ink-secondary">{eventTypeLabel(event.type)}</div>
        </div>
      ),
    },
    {
      id: "package",
      header: "Package",
      cell: (event) => (
        <div className="flex min-w-0 max-w-xs flex-col items-start gap-0.5">
          {event.package ? (
            <code className="break-all font-mono text-[0.8125rem] text-ink">
              {revealInvisible(event.package)}
              {event.version ? <span className="text-ink-muted">=={revealInvisible(event.version)}</span> : null}
            </code>
          ) : (
            <span className="text-ink-muted">None</span>
          )}
          {event.scan_id && (
            <Link to={scanPath(event.scan_id)} className="text-xs text-accent hover:underline">
              Open scan <span className="sr-only">for {revealInvisible(event.title)}</span>
            </Link>
          )}
        </div>
      ),
    },
    { id: "recorded", header: "Recorded", cell: (event) => <RelativeTime value={event.created_at} now={reference} /> },
    {
      id: "status",
      header: "Status",
      cell: (event) => {
        const view = acks.view(event);
        return (
          <AckControl
            view={view}
            canAcknowledge={canAcknowledge}
            subject={`event ${event.title}`}
            onAcknowledge={() => void acks.acknowledge(view.event)}
          />
        );
      },
    },
  ];

  return (
    <>
      <PageHeader
        title="Security events"
        description="Blocked packages, new vulnerabilities, behaviour drift and policy exception changes recorded by this deployment, newest first."
        actions={
          <AutoRefreshControl
            enabled={autoRefresh}
            onToggle={(enabled) => {
              setAutoRefresh(enabled);
              storeAutoRefreshPreference(enabled);
            }}
            hidden={hidden}
            intervalSeconds={EVENTS_REFRESH_INTERVAL_MS / 1000}
            lastUpdatedAt={query.data?.fetchedAt}
            now={now}
            refreshing={query.loading && query.data !== undefined}
            onRefresh={query.reload}
          />
        }
      />

      <InvalidParamsNotice
        labels={ignored.map((name) => EVENT_FILTER_LABEL[name])}
        onRemove={() => updateParams(Object.fromEntries(ignored.map((name) => [name, null])))}
      />
      <EventFilterBar filters={filters} onChange={updateParams} />

      <p role="status" className="sr-only">
        {acks.announcement}
      </p>
      {failure && failure.event.id !== selectedView?.event.id && (
        <div className="mb-3 flex flex-wrap items-start gap-2">
          <div className="min-w-0 flex-1">
            <ErrorState
              title={`Not acknowledged: ${revealInvisible(failure.event.title)}`}
              error={failure.error}
              onRetry={() => void acks.acknowledge(failure.event)}
            />
          </div>
          <button type="button" className="btn-ghost" onClick={acks.dismissFailure}>
            Dismiss
          </button>
        </div>
      )}

      <Card flush>
        <div ref={tableRegionRef} tabIndex={-1} className="focus:outline-none">
          <DataTable
            caption="Security events"
            columns={columns}
            rows={page?.items}
            rowKey={(event) => event.id}
            // A background refresh keeps the rows as they are; only a new filter or page dims them.
            loading={query.loading && query.data === undefined}
            error={query.error}
            onRetry={query.reload}
            empty={
              pastEnd ? (
                <EmptyState
                  compact
                  title="This page is past the end of the list."
                  action={
                    <button type="button" className="btn-secondary" onClick={() => updateParams({ offset: null })}>
                      Go to the first page
                    </button>
                  }
                />
              ) : (
                <EmptyState
                  compact
                  title={active ? "No security events match these filters." : "No security events recorded yet."}
                  description={
                    active
                      ? "Change or clear the filters."
                      : "Events appear when scans block packages, vulnerabilities are found or policy exceptions change."
                  }
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
            footnote="Newest first."
          />
        </div>
      </Card>

      <EventDetailDrawer
        view={selectedView}
        now={reference}
        currentUserId={currentUserId}
        canAcknowledge={canAcknowledge}
        failure={failure}
        onAcknowledge={(event) => void acks.acknowledge(event)}
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

/** Security events (event:read), with acknowledgement for roles holding event:ack. */
export default function Events() {
  return (
    <RequirePermission permission={PERMISSIONS.EVENT_READ}>
      <EventsView />
    </RequirePermission>
  );
}
