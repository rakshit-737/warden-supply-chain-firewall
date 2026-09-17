import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { getPackage } from "../api/packages";
import type { PackageVerdict } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { DecisionBadge } from "../components/DecisionBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { LoadingBlock } from "../components/Skeleton";
import { DriftLabel } from "../features/diffs/DriftLabel";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime } from "../lib/format";
import { LINK_CLASS } from "../lib/styles";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$/;

const VERDICT_COLUMNS: Column<PackageVerdict>[] = [
  {
    id: "version",
    header: "Version",
    cell: (v) => (
      <Link to={`/scans/${encodeURIComponent(v.scan_id)}`} className={`${LINK_CLASS} font-mono text-[0.8125rem]`}>
        {v.version}
      </Link>
    ),
    sortValue: (v) => v.version,
  },
  { id: "environment", header: "Environment", cell: (v) => v.environment },
  { id: "decision", header: "Decision", cell: (v) => <DecisionBadge value={v.decision} /> },
  { id: "risk", header: "Risk", cell: (v) => v.risk_score, sortValue: (v) => v.risk_score, align: "right" },
  { id: "scanned", header: "Scanned", cell: (v) => formatDateTime(v.scanned_at), sortValue: (v) => v.scanned_at },
];

function Overview({ name }: { name: string }) {
  const query = useApiQuery(`package:${name}`, (signal) => getPackage("pypi", name, { signal }));
  if (query.error) {
    return query.error.status === 404 ? (
      <EmptyState
        title="Warden has no data for this package yet."
        description="Scan a release, watch the package or compare two releases to start its history."
        action={
          <Link to="/scans/new" className="btn-primary">
            Scan a release
          </Link>
        }
      />
    ) : (
      <ErrorState error={query.error} onRetry={query.reload} />
    );
  }
  const data = query.data;
  if (!data) return <LoadingBlock label="Loading package" />;
  const latest = data.latest_verdict;

  return (
    <div className="flex flex-col gap-4">
      <Card title={<span className="font-mono">{data.name}</span>}>
        {latest ? (
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <DecisionBadge value={latest.decision} size="lg" />
            <span>
              Latest verdict: <span className="font-mono">{latest.version}</span> in {latest.environment}, risk{" "}
              {latest.risk_score}, {formatDateTime(latest.scanned_at)}
            </span>
          </div>
        ) : (
          <p className="text-sm text-ink-secondary">No stored verdicts; this package is only watched or compared.</p>
        )}
      </Card>
      <DataTable
        caption="Stored verdicts"
        showCaption
        columns={VERDICT_COLUMNS}
        rows={data.verdicts}
        rowKey={(v) => v.scan_id}
        empty={<EmptyState title="No verdicts stored." compact />}
      />
      <Card title="Known advisories in stored verdicts">
        {data.vulnerabilities.length ? (
          <ul className="flex flex-col gap-1 text-sm">
            {data.vulnerabilities.map((v) => (
              <li key={v.id}>
                <code className="font-mono">{v.id}</code> · {v.severity ?? "unknown"}
                {v.kev ? " · known exploited" : ""} · affects {v.versions.join(", ")}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-ink-secondary">
            None recorded. Scans run without vulnerability intelligence cannot rule advisories out.
          </p>
        )}
      </Card>
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Monitoring">
          {data.monitoring.length ? (
            <ul className="flex flex-col gap-1 text-sm">
              {data.monitoring.map((m) => (
                <li key={m.id}>
                  {m.enabled ? "Watching" : "Paused"} · approved {m.approved_version ?? "—"} · latest seen{" "}
                  {m.latest_seen_version ?? "—"}
                  {m.consecutive_failures ? ` · ${m.consecutive_failures} failed checks` : ""}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-ink-secondary">
              Not watched. <Link to="/monitoring" className={LINK_CLASS}>Watch it</Link>
            </p>
          )}
        </Card>
        <Card title="Release comparisons">
          {data.release_diffs.length ? (
            <ul className="flex flex-col gap-1 text-sm">
              {data.release_diffs.map((d) => (
                <li key={d.id} className="flex flex-wrap items-center gap-2">
                  <Link to={`/diffs/${encodeURIComponent(d.id)}`} className={`${LINK_CLASS} font-mono`}>
                    {d.old_version} → {d.new_version}
                  </Link>
                  <DriftLabel drift={d.drift_detected} />
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-ink-secondary">No releases compared.</p>
          )}
        </Card>
      </div>
    </div>
  );
}

function PackagesView() {
  const [searchParams, setSearchParams] = useSearchParams();
  const current = searchParams.get("name") ?? "";
  const [draft, setDraft] = useState(current);
  const valid = NAME_RE.test(current);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = draft.trim();
    setSearchParams(name ? { name } : {});
  }

  return (
    <>
      <PageHeader title="Packages" description="Everything Warden has recorded about one PyPI package." />
      <div className="flex flex-col gap-4">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3" role="search">
          <div className="min-w-64 flex-1">
            <label htmlFor="package-name" className="label">
              PyPI package name
            </label>
            <input id="package-name" className="input font-mono" value={draft} onChange={(e) => setDraft(e.target.value)} />
          </div>
          <button type="submit" className="btn-primary" disabled={!draft.trim()}>
            Look up
          </button>
        </form>
        {current && !valid && <ErrorState error="That is not a valid PyPI package name." title="Invalid name" />}
        {current && valid && <Overview key={current} name={current} />}
        {!current && <EmptyState title="Enter a package name to see its history." compact />}
      </div>
    </>
  );
}

export default function Packages() {
  return (
    <RequirePermission permission={PERMISSIONS.SCAN_READ}>
      <PackagesView />
    </RequirePermission>
  );
}
