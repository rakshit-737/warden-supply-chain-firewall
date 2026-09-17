import { useParams } from "react-router";
import { getDiff } from "../api/diffs";
import type { DiffFinding, ReleaseDiffSummary } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { KeyValueList } from "../components/KeyValueList";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { SeverityBadge } from "../components/SeverityBadge";
import { LoadingBlock } from "../components/Skeleton";
import { DriftLabel } from "../features/diffs/DriftLabel";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime, humanize } from "../lib/format";

const FINDING_COLUMNS: Column<DiffFinding>[] = [
  { id: "severity", header: "Severity", cell: (f) => <SeverityBadge value={f.severity} /> },
  { id: "code", header: "Finding", cell: (f) => <code className="font-mono text-2xs">{f.code}</code>, sortValue: (f) => f.code },
  { id: "where", header: "Location", cell: (f) => (f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : "—") },
  { id: "message", header: "Message", cell: (f) => <span className="wrap-break-word">{f.message}</span> },
];

function List({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <div>
      <h3 className="mb-1 text-sm font-semibold">{title}</h3>
      {items.length ? (
        <ul className="list-disc pl-5 font-mono text-2xs">
          {items.map((item) => (
            <li key={item} className="break-all">
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-ink-secondary">{empty}</p>
      )}
    </div>
  );
}

function Summary({ summary }: { summary: ReleaseDiffSummary }) {
  const { risk, capabilities, files, maintainers } = summary;
  const dimensions = Object.entries(risk.dimensions);
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Risk">
        <KeyValueList
          items={[
            { term: "Score", value: `${risk.from} (${risk.from_severity}) → ${risk.to} (${risk.to_severity})` },
            { term: "Change", value: risk.delta > 0 ? `+${risk.delta}` : String(risk.delta) },
            ...dimensions.map(([name, change]) => ({
              key: name,
              term: humanize(name),
              value: `${change.from ?? "—"} → ${change.to ?? "—"}`,
            })),
          ]}
        />
      </Card>
      <Card title="Capabilities and maintainers">
        <div className="flex flex-col gap-3">
          <List title="New capabilities" items={capabilities.added} empty="None" />
          <List title="Removed capabilities" items={capabilities.removed} empty="None" />
          {maintainers.available ? (
            <List title="New maintainers" items={maintainers.added ?? []} empty="None" />
          ) : (
            <p className="text-sm text-ink-secondary">Maintainer information was not available for both releases.</p>
          )}
        </div>
      </Card>
      <Card title="Files" className="lg:col-span-2">
        {files.available ? (
          <div className="flex flex-col gap-3">
            <p className="text-sm">
              {files.added_count} added, {files.removed_count} removed, {files.changed_count} changed.
            </p>
            <div className="grid gap-4 md:grid-cols-2">
              <List title="Install- or start-up-time files changed" items={files.install_time_changes} empty="None" />
              <List title="New executable binaries" items={files.new_executable_binaries} empty="None" />
              <List title="Added files" items={files.added} empty="None" />
              <List title="Changed files" items={files.changed} empty="None" />
            </div>
          </div>
        ) : (
          <p className="text-sm text-ink-secondary">File comparison unavailable: {files.reason}.</p>
        )}
      </Card>
    </div>
  );
}

function DiffDetailView() {
  const { id = "" } = useParams();
  const query = useApiQuery(`diff:${id}`, (signal) => getDiff(id, { signal }));
  const back = { to: "/diffs", label: "Release diffs" };

  if (query.error) {
    return (
      <>
        <PageHeader title="Release diff" back={back} />
        <ErrorState error={query.error} title="This comparison could not be loaded" onRetry={query.reload} />
      </>
    );
  }
  const diff = query.data;
  if (!diff) return <LoadingBlock label="Loading comparison" />;

  return (
    <>
      <PageHeader
        title={`${diff.package} ${diff.old_version} → ${diff.new_version}`}
        heading={
          <span className="font-mono">
            {diff.package} <span className="text-ink-muted">{diff.old_version} → {diff.new_version}</span>
          </span>
        }
        back={back}
        meta={
          <>
            <DriftLabel drift={diff.drift_detected} /> · compared {formatDateTime(diff.created_at)} · analyzer{" "}
            {diff.analyzer_version}
          </>
        }
      />
      <div className="flex flex-col gap-4">
        {diff.summary?.reasons.length ? (
          <Card title="Why this counts as drift">
            <ul className="list-disc pl-5 text-sm">
              {diff.summary.reasons.map((r) => (
                <li key={r} className="wrap-break-word">
                  {r}
                </li>
              ))}
            </ul>
          </Card>
        ) : null}
        {diff.summary ? <Summary summary={diff.summary} /> : <EmptyState title="No summary was stored." compact />}
        <DataTable
          caption="New findings in the newer release"
          showCaption
          columns={FINDING_COLUMNS}
          rows={diff.findings ?? []}
          rowKey={(f) => `${f.code}:${f.file ?? ""}`}
          empty={<EmptyState title="No new findings." compact />}
        />
      </div>
    </>
  );
}

export default function DiffDetail() {
  return (
    <RequirePermission permission={PERMISSIONS.SCAN_READ}>
      <DiffDetailView />
    </RequirePermission>
  );
}
