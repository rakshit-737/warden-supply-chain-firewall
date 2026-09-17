import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { toApiError, type ApiError } from "../api/client";
import {
  addMonitoredPackage,
  checkMonitoredPackage,
  listMonitoredPackages,
  removeMonitoredPackage,
  updateMonitoredPackage,
} from "../api/monitoring";
import type { MonitoredPackage, MonitoringCheckResult } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime } from "../lib/format";
import { LINK_CLASS } from "../lib/styles";

const PAGE_SIZE = 50;

const CHECK_TEXT: Record<string, string> = {
  baseline: "Baseline recorded",
  unchanged: "No new release",
  new_release: "New release analysed",
  error: "Check failed",
};

function AddForm({ onAdded }: { onAdded: () => void }) {
  const [name, setName] = useState("");
  const [approved, setApproved] = useState("");
  const [hours, setHours] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await addMonitoredPackage({
        name: name.trim(),
        approved_version: approved.trim() || null,
        poll_interval_seconds: Math.round(hours * 3600),
      });
      setName("");
      setApproved("");
      onAdded();
    } catch (err) {
      setError(toApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Watch a package"
      description="New releases are analysed and compared with the approved version (or the last one seen)."
    >
      <form
        onSubmit={(event) => void submit(event)}
        className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_8rem_auto] sm:items-end"
      >
        <div>
          <label htmlFor="watch-name" className="label">
            PyPI package
          </label>
          <input id="watch-name" className="input font-mono" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <label htmlFor="watch-approved" className="label">
            Approved version (optional)
          </label>
          <input id="watch-approved" className="input font-mono" value={approved} onChange={(e) => setApproved(e.target.value)} />
        </div>
        <div>
          <label htmlFor="watch-interval" className="label">
            Check every (hours)
          </label>
          <input
            id="watch-interval"
            type="number"
            min={0.5}
            max={168}
            step={0.5}
            className="input"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
          />
        </div>
        <button type="submit" className="btn-primary" disabled={busy || !name.trim()}>
          {busy ? "Adding…" : "Watch"}
        </button>
      </form>
      {error && (
        <div className="mt-3">
          <ErrorState error={error} title="The package was not added" />
        </div>
      )}
    </Card>
  );
}

function MonitoringView() {
  const canWrite = usePermission(PERMISSIONS.MONITOR_WRITE);
  const [searchParams, setSearchParams] = useSearchParams();
  const offset = Math.max(0, Number.parseInt(searchParams.get("offset") ?? "0", 10) || 0);
  const failing = searchParams.get("failing") === "1";
  const query = useApiQuery(`monitoring:${offset}:${failing}`, (signal) =>
    listMonitoredPackages({ limit: PAGE_SIZE, offset, failing: failing || undefined }, { signal }),
  );
  const page = query.data ?? query.previousData;
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [lastCheck, setLastCheck] = useState<MonitoringCheckResult | null>(null);

  async function act(row: MonitoredPackage, action: () => Promise<unknown>) {
    setBusyId(row.id);
    setActionError(null);
    try {
      const result = await action();
      if (result && typeof result === "object" && "status" in result) setLastCheck(result as MonitoringCheckResult);
      query.reload();
    } catch (err) {
      setActionError(toApiError(err));
    } finally {
      setBusyId(null);
    }
  }

  const columns: Column<MonitoredPackage>[] = [
    {
      id: "name",
      header: "Package",
      cell: (m) => (
        <Link to={`/packages?name=${encodeURIComponent(m.name)}`} className={`${LINK_CLASS} font-mono text-[0.8125rem]`}>
          {m.name}
        </Link>
      ),
      sortValue: (m) => m.name,
    },
    { id: "approved", header: "Approved", cell: (m) => m.approved_version ?? "—" },
    { id: "latest", header: "Latest seen", cell: (m) => m.latest_seen_version ?? "Not checked yet" },
    { id: "risk", header: "Risk", cell: (m) => m.last_risk_score ?? "—", sortValue: (m) => m.last_risk_score, align: "right" },
    {
      id: "checked",
      header: "Last check",
      cell: (m) =>
        m.consecutive_failures > 0 ? (
          <span className="font-semibold">{m.consecutive_failures} failed in a row</span>
        ) : m.last_checked_at ? (
          formatDateTime(m.last_checked_at)
        ) : (
          "Never"
        ),
    },
    { id: "enabled", header: "Watching", cell: (m) => (m.enabled ? "Yes" : "Paused"), sortValue: (m) => m.enabled },
  ];
  if (canWrite) {
    columns.push({
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (m) => (
        <div className="flex flex-wrap justify-end gap-1.5">
          <button
            type="button"
            className="btn-secondary"
            disabled={busyId !== null}
            onClick={() => void act(m, () => checkMonitoredPackage(m.id))}
          >
            {busyId === m.id ? "Working…" : "Check now"}
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={busyId !== null}
            onClick={() => void act(m, () => updateMonitoredPackage(m.id, { enabled: !m.enabled }))}
          >
            {m.enabled ? "Pause" : "Resume"}
          </button>
          <button
            type="button"
            className="btn-danger"
            disabled={busyId !== null}
            aria-label={`Stop watching ${m.name}`}
            onClick={() => void act(m, () => removeMonitoredPackage(m.id))}
          >
            Remove
          </button>
        </div>
      ),
      align: "right",
    });
  }

  return (
    <>
      <PageHeader
        title="Monitoring"
        description="Packages watched for new releases, behaviour drift and maintainer changes. Checks run in the monitoring worker."
      />
      <div className="flex flex-col gap-4">
        {canWrite && <AddForm onAdded={query.reload} />}
        {lastCheck && (
          <p role="status" className="rounded-md border border-line bg-panel px-4 py-2 text-sm">
            {lastCheck.package}: {CHECK_TEXT[lastCheck.status] ?? lastCheck.status}
            {lastCheck.version ? ` (${lastCheck.version})` : ""}
            {lastCheck.detail ? ` — ${lastCheck.detail}` : ""}
            {lastCheck.diff_id && (
              <>
                {" "}
                <Link to={`/diffs/${encodeURIComponent(lastCheck.diff_id)}`} className={LINK_CLASS}>
                  View comparison
                </Link>
              </>
            )}
          </p>
        )}
        {actionError && <ErrorState error={actionError} title="The action did not complete" />}
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={failing}
            onChange={(e) => setSearchParams(e.target.checked ? { failing: "1" } : {})}
          />
          Only packages whose checks are failing
        </label>
        <DataTable
          caption="Watched packages"
          columns={columns}
          rows={page?.items}
          rowKey={(m) => m.id}
          loading={query.loading}
          error={query.error}
          onRetry={query.reload}
          empty={<EmptyState title={failing ? "No checks are failing." : "No packages are being watched."} />}
          pagination={
            page
              ? {
                  total: page.total,
                  limit: page.limit,
                  offset: page.offset,
                  onOffsetChange: (next) =>
                    setSearchParams({ ...(failing ? { failing: "1" } : {}), ...(next ? { offset: String(next) } : {}) }),
                }
              : undefined
          }
        />
      </div>
    </>
  );
}

export default function Monitoring() {
  return (
    <RequirePermission permission={PERMISSIONS.MONITOR_READ}>
      <MonitoringView />
    </RequirePermission>
  );
}
