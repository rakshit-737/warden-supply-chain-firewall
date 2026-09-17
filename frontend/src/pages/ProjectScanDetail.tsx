import { useState } from "react";
import { useParams } from "react-router";
import { toApiError, type ApiError } from "../api/client";
import { getProjectScan, getProjectScanGraph, getProjectScanSbom, listProjectScanComponents } from "../api/projects";
import type { GraphNode, ProjectComponent, SbomFormat } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { DecisionBadge } from "../components/DecisionBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { FindingCard } from "../components/FindingCard";
import { KeyValueList } from "../components/KeyValueList";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { LoadingBlock } from "../components/Skeleton";
import { Tabs } from "../components/Tabs";
import { useApiQuery } from "../hooks/useApiQuery";
import { downloadText, safeFileName } from "../lib/download";
import { formatDateTime, formatPercent } from "../lib/format";

const COMPONENT_PAGE = 100;

const COMPONENT_COLUMNS: Column<ProjectComponent>[] = [
  {
    id: "name",
    header: "Package",
    cell: (c) => (
      <span className="wrap-break-word font-mono text-[0.8125rem]">
        {c.name}
        {c.version && <span className="text-ink-muted">=={c.version}</span>}
      </span>
    ),
    sortValue: (c) => c.name.toLowerCase(),
  },
  { id: "direct", header: "Direct", cell: (c) => (c.direct ? "Yes" : "No"), sortValue: (c) => c.direct },
  { id: "resolution", header: "Resolution", cell: (c) => c.resolution ?? "—" },
  { id: "decision", header: "Stored verdict", cell: (c) => (c.decision ? <DecisionBadge value={c.decision} /> : "Not scanned") },
  { id: "risk", header: "Risk", cell: (c) => c.risk_score ?? "—", sortValue: (c) => c.risk_score, align: "right" },
  {
    id: "declared",
    header: "Declared in",
    cell: (c) =>
      (c.declared_at ?? [])
        .slice(0, 3)
        .map((d) => (d.line ? `${d.file}:${d.line}` : d.file))
        .join(", ") || "—",
  },
];

const NODE_COLUMNS: Column<GraphNode>[] = [
  { id: "name", header: "Package", cell: (n) => <span className="font-mono text-[0.8125rem]">{n.name}</span>, sortValue: (n) => n.name },
  { id: "depth", header: "Depth", cell: (n) => n.depth ?? "—", sortValue: (n) => n.depth, align: "right" },
  {
    id: "blast",
    header: "Blast radius",
    cell: (n) => (n.blast_radius === null ? "—" : formatPercent(n.blast_radius)),
    sortValue: (n) => n.blast_radius,
    align: "right",
  },
  { id: "dependents", header: "Dependents", cell: (n) => n.transitive_dependents, sortValue: (n) => n.transitive_dependents, align: "right" },
  { id: "single", header: "Single point", cell: (n) => (n.is_single_point ? "Yes" : "No"), sortValue: (n) => n.is_single_point },
  { id: "risk", header: "Risk", cell: (n) => n.risk ?? "—", sortValue: (n) => n.risk, align: "right" },
];

function ComponentsTab({ projectId, scanId }: { projectId: string; scanId: string }) {
  const [offset, setOffset] = useState(0);
  const query = useApiQuery(`project-components:${scanId}:${offset}`, (signal) =>
    listProjectScanComponents(projectId, scanId, { limit: COMPONENT_PAGE, offset }, { signal }),
  );
  const page = query.data ?? query.previousData;
  return (
    <DataTable
      caption="Components"
      columns={COMPONENT_COLUMNS}
      rows={page?.items}
      rowKey={(c) => c.bom_ref}
      loading={query.loading}
      error={query.error}
      onRetry={query.reload}
      empty={<EmptyState title="No components were found in the manifests." compact />}
      pagination={page ? { total: page.total, limit: page.limit, offset: page.offset, onOffsetChange: setOffset } : undefined}
    />
  );
}

function GraphTab({ projectId, scanId }: { projectId: string; scanId: string }) {
  const query = useApiQuery(`project-graph:${scanId}`, (signal) => getProjectScanGraph(projectId, scanId, { signal }));
  if (query.error) return <ErrorState error={query.error} onRetry={query.reload} />;
  if (!query.data) return <LoadingBlock label="Loading dependency graph" />;
  const { metrics, nodes } = query.data;
  const packages = nodes.filter((n) => n.type === "package");
  return (
    <div className="flex flex-col gap-4">
      <Card title="Graph metrics">
        <KeyValueList
          columns={2}
          items={[
            { term: "Packages", value: packages.length },
            { term: "Edges", value: metrics.edge_count },
            { term: "Maximum depth", value: metrics.max_depth },
            { term: "Direct / transitive", value: `${metrics.direct_count ?? "—"} / ${metrics.transitive_count ?? "—"}` },
            { term: "Cycles", value: Boolean(metrics.has_cycles) },
            { term: "Single points of failure", value: (metrics.single_points ?? []).length },
          ]}
        />
      </Card>
      <DataTable
        caption="Packages by blast radius"
        showCaption
        columns={NODE_COLUMNS}
        rows={packages}
        rowKey={(n) => n.id}
        defaultSort={{ columnId: "blast", direction: "desc" }}
        empty={<EmptyState title="The graph has no package nodes." compact />}
        footnote="Blast radius: share of the project's packages that depend on this one, directly or transitively."
      />
    </div>
  );
}

function SbomButtons({ projectId, scanId, name }: { projectId: string; scanId: string; name: string }) {
  const [busy, setBusy] = useState<SbomFormat | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  async function download(format: SbomFormat) {
    setBusy(format);
    setError(null);
    try {
      const text = await getProjectScanSbom(projectId, scanId, format);
      downloadText(safeFileName(`${name}-${format}`, "json"), text);
    } catch (err) {
      setError(toApiError(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex gap-2">
        <button type="button" className="btn-secondary" disabled={busy !== null} onClick={() => void download("cyclonedx")}>
          {busy === "cyclonedx" ? "Preparing…" : "CycloneDX SBOM"}
        </button>
        <button type="button" className="btn-secondary" disabled={busy !== null} onClick={() => void download("spdx")}>
          {busy === "spdx" ? "Preparing…" : "SPDX SBOM"}
        </button>
      </div>
      {error && <ErrorState error={error} title="The SBOM could not be exported" />}
    </div>
  );
}

function ProjectScanView() {
  const { id = "", scanId = "" } = useParams();
  const query = useApiQuery(`project-scan:${scanId}`, (signal) => getProjectScan(id, scanId, { signal }));
  const back = { to: `/projects/${encodeURIComponent(id)}`, label: "Project" };

  if (query.error) {
    return (
      <>
        <PageHeader title="Project scan" back={back} />
        <ErrorState error={query.error} title="This project scan could not be loaded" onRetry={query.reload} />
      </>
    );
  }
  const scan = query.data;
  if (!scan) return <LoadingBlock label="Loading project scan" />;
  const findings = scan.summary?.findings ?? [];
  const warnings = scan.summary?.warnings ?? [];

  return (
    <>
      <PageHeader
        title="Project scan"
        back={back}
        meta={formatDateTime(scan.created_at)}
        actions={<SbomButtons projectId={id} scanId={scanId} name={`project-${scan.project_id}`} />}
      />
      <div className="flex flex-col gap-4">
        <Card>
          <div className="flex flex-wrap items-center gap-6">
            <DecisionBadge value={scan.decision} size="lg" />
            <KeyValueList
              columns={2}
              items={[
                { term: "Risk score", value: scan.risk_score },
                { term: "Environment", value: scan.environment },
                { term: "Components", value: `${scan.component_count} (${scan.direct_count} direct)` },
                { term: "With a stored verdict", value: scan.summary?.components_with_verdict ?? 0 },
                { term: "Manifests", value: (scan.manifests ?? []).map((m) => m.file).join(", "), mono: true },
              ]}
            />
          </div>
        </Card>
        {warnings.length > 0 && (
          <Card title="Parser warnings" description="Parts of the manifests Warden could not interpret; the inventory may be incomplete.">
            <ul className="list-disc pl-5 text-sm">
              {warnings.map((w) => (
                <li key={w} className="wrap-break-word">
                  {w}
                </li>
              ))}
            </ul>
          </Card>
        )}
        <Tabs
          label="Project scan details"
          tabs={[
            {
              id: "findings",
              label: "Findings",
              count: findings.length,
              content: findings.length ? (
                <div className="flex flex-col gap-2">
                  {findings.map((f, index) => (
                    <FindingCard key={f.finding_id ?? `${f.code}-${index}`} finding={f} />
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No hygiene, confusion or container findings."
                  description="This covers how dependencies are declared and sourced, not the packages' own code; scan packages for that."
                  compact
                />
              ),
            },
            { id: "components", label: "Components", count: scan.component_count, content: <ComponentsTab projectId={id} scanId={scanId} /> },
            { id: "graph", label: "Dependency graph", content: <GraphTab projectId={id} scanId={scanId} /> },
          ]}
        />
      </div>
    </>
  );
}

export default function ProjectScanDetail() {
  return (
    <RequirePermission permission={PERMISSIONS.PROJECT_READ}>
      <ProjectScanView />
    </RequirePermission>
  );
}
