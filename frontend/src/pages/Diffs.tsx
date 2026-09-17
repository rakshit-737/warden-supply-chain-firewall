import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { toApiError, type ApiError } from "../api/client";
import { createDiff, listDiffs } from "../api/diffs";
import type { ReleaseDiffListItem } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { DriftLabel } from "../features/diffs/DriftLabel";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime } from "../lib/format";
import { LINK_CLASS } from "../lib/styles";

const PAGE_SIZE = 25;

const COLUMNS: Column<ReleaseDiffListItem>[] = [
  {
    id: "package",
    header: "Package",
    cell: (d) => (
      <Link to={`/diffs/${encodeURIComponent(d.id)}`} className={`${LINK_CLASS} font-mono text-[0.8125rem]`}>
        {d.package} {d.old_version} → {d.new_version}
      </Link>
    ),
    sortValue: (d) => d.package,
  },
  { id: "drift", header: "Result", cell: (d) => <DriftLabel drift={d.drift_detected} />, sortValue: (d) => d.drift_detected },
  { id: "delta", header: "Risk increase", cell: (d) => d.drift_score, sortValue: (d) => d.drift_score, align: "right" },
  { id: "created", header: "Compared", cell: (d) => formatDateTime(d.created_at), sortValue: (d) => d.created_at },
];

function CreateDiffForm() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [fromVersion, setFromVersion] = useState("");
  const [toVersion, setToVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const ready = name.trim() && fromVersion.trim() && toVersion.trim();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      const diff = await createDiff({ name: name.trim(), from_version: fromVersion.trim(), to_version: toVersion.trim() });
      void navigate(`/diffs/${encodeURIComponent(diff.id)}`);
    } catch (err) {
      setError(toApiError(err));
      setBusy(false);
    }
  }

  return (
    <Card
      title="Compare two releases"
      description="Both releases are downloaded and analysed; nothing is installed or run. This can take a few minutes."
    >
      <form onSubmit={(event) => void submit(event)} className="grid gap-4 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end">
        <div>
          <label htmlFor="diff-name" className="label">
            PyPI package
          </label>
          <input id="diff-name" className="input font-mono" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <label htmlFor="diff-from" className="label">
            From version
          </label>
          <input id="diff-from" className="input font-mono" value={fromVersion} onChange={(e) => setFromVersion(e.target.value)} />
        </div>
        <div>
          <label htmlFor="diff-to" className="label">
            To version
          </label>
          <input id="diff-to" className="input font-mono" value={toVersion} onChange={(e) => setToVersion(e.target.value)} />
        </div>
        <button type="submit" className="btn-primary" disabled={!ready || busy}>
          {busy ? "Comparing…" : "Compare"}
        </button>
      </form>
      {busy && (
        <p role="status" className="mt-3 text-sm text-ink-secondary">
          Analysing both releases…
        </p>
      )}
      {error && (
        <div className="mt-3">
          <ErrorState error={error} title="The comparison did not complete" />
        </div>
      )}
    </Card>
  );
}

function DiffsView() {
  const canCreate = usePermission(PERMISSIONS.DIFF_CREATE);
  const [searchParams, setSearchParams] = useSearchParams();
  const offset = Math.max(0, Number.parseInt(searchParams.get("offset") ?? "0", 10) || 0);
  const driftOnly = searchParams.get("drift") === "1";
  const query = useApiQuery(`diffs:${offset}:${driftOnly}`, (signal) =>
    listDiffs({ limit: PAGE_SIZE, offset, drift_only: driftOnly || undefined }, { signal }),
  );
  const page = query.data ?? query.previousData;

  function setParam(next: { offset?: number; drift?: boolean }) {
    const params: Record<string, string> = {};
    const drift = next.drift ?? driftOnly;
    if (drift) params.drift = "1";
    if (next.offset) params.offset = String(next.offset);
    setSearchParams(params);
  }

  return (
    <>
      <PageHeader
        title="Release diffs"
        description="What changed in behaviour between two releases: risk, capabilities, findings, files and maintainers."
      />
      <div className="flex flex-col gap-4">
        {canCreate && <CreateDiffForm />}
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={driftOnly} onChange={(e) => setParam({ drift: e.target.checked, offset: 0 })} />
          Only comparisons with drift
        </label>
        <DataTable
          caption="Release diffs"
          columns={COLUMNS}
          rows={page?.items}
          rowKey={(d) => d.id}
          loading={query.loading}
          error={query.error}
          onRetry={query.reload}
          empty={<EmptyState title={driftOnly ? "No comparison found drift." : "No releases have been compared yet."} />}
          pagination={
            page
              ? { total: page.total, limit: page.limit, offset: page.offset, onOffsetChange: (o) => setParam({ offset: o }) }
              : undefined
          }
        />
      </div>
    </>
  );
}

export default function Diffs() {
  return (
    <RequirePermission permission={PERMISSIONS.SCAN_READ}>
      <DiffsView />
    </RequirePermission>
  );
}
