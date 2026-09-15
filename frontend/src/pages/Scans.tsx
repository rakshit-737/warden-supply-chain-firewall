import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { listScans } from "../api/scans";
import { DECISIONS, ENVIRONMENTS, SEVERITIES, type ListScansParams } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { SelectField } from "../components/SelectField";
import { useApiQuery } from "../hooks/useApiQuery";
import { humanize } from "../lib/format";
import { DECISION_LABEL, SEVERITY_LABEL } from "../lib/risk";
import { pickOption } from "../lib/values";
import { scanSummaryColumns } from "./scanColumns";

const PAGE_SIZE = 25;
const COLUMNS = scanSummaryColumns({ showEnvironment: true });

function parseOffset(value: string | null): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : 0;
}

export default function Scans() {
  const canScan = usePermission(PERMISSIONS.SCAN_CREATE);
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get("q") ?? "";
  const decision = pickOption(DECISIONS, searchParams.get("decision"));
  const severity = pickOption(SEVERITIES, searchParams.get("severity"));
  const environment = pickOption(ENVIRONMENTS, searchParams.get("environment"));
  const offset = parseOffset(searchParams.get("offset"));

  // The text box follows the URL unless the user has typed since the URL last changed.
  const [typed, setTyped] = useState({ basedOn: q, value: q });
  const searchText = typed.basedOn === q ? typed.value : q;

  const updateParams = useCallback(
    (changes: Record<string, string | null>) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [name, value] of Object.entries(changes)) {
            if (value === null || value === "") next.delete(name);
            else next.set(name, value);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  // Apply typed text to the URL after a short pause.
  useEffect(() => {
    if (typed.basedOn !== q || typed.value === q) return;
    const timer = window.setTimeout(() => updateParams({ q: typed.value, offset: null }), 300);
    return () => window.clearTimeout(timer);
  }, [typed, q, updateParams]);

  const params: ListScansParams = {
    limit: PAGE_SIZE,
    offset,
    q: q.trim() || undefined,
    decision,
    severity,
    environment,
  };
  const query = useApiQuery(`scans:${JSON.stringify(params)}`, (signal) => listScans(params, { signal }));
  const page = query.data ?? query.previousData;
  const filtered = Boolean(q.trim() || decision || severity || environment);

  // An offset beyond the last scan (an old bookmark or shared link, or scans removed since) returns no
  // rows although scans exist. Move to the last page rather than showing an empty list.
  const current = query.data;
  const pastEnd = current !== undefined && current.total > 0 && current.items.length === 0 && offset > 0;
  const lastPageOffset = current ? Math.floor(Math.max(current.total - 1, 0) / (current.limit || PAGE_SIZE)) * (current.limit || PAGE_SIZE) : 0;
  useEffect(() => {
    if (!pastEnd || lastPageOffset === offset) return;
    updateParams({ offset: lastPageOffset > 0 ? String(lastPageOffset) : null });
  }, [pastEnd, lastPageOffset, offset, updateParams]);

  return (
    <>
      <PageHeader
        title="Scans"
        description="Every package analysis recorded by this deployment, newest first."
        actions={
          canScan ? (
            <Link to="/scans/new" className="btn-primary">
              New scan
            </Link>
          ) : undefined
        }
      />

      <div role="search" aria-label="Filter scans" className="mb-3 flex flex-wrap items-end gap-3">
        <div className="w-full sm:w-64">
          <label htmlFor="scan-filter-q" className="label">
            Package name
          </label>
          <input
            id="scan-filter-q"
            type="search"
            className="input"
            placeholder="Contains"
            maxLength={214}
            spellCheck={false}
            value={searchText}
            onChange={(event) => setTyped({ basedOn: q, value: event.target.value })}
          />
        </div>
        <SelectField
          id="scan-filter-decision"
          label="Decision"
          className="w-32"
          value={decision ?? ""}
          options={[{ value: "", label: "Any" }, ...DECISIONS.map((d) => ({ value: d, label: DECISION_LABEL[d] }))]}
          onChange={(value) => updateParams({ decision: value, offset: null })}
        />
        <SelectField
          id="scan-filter-severity"
          label="Severity"
          className="w-32"
          value={severity ?? ""}
          options={[{ value: "", label: "Any" }, ...SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))]}
          onChange={(value) => updateParams({ severity: value, offset: null })}
        />
        <SelectField
          id="scan-filter-environment"
          label="Environment"
          className="w-36"
          value={environment ?? ""}
          options={[{ value: "", label: "Any" }, ...ENVIRONMENTS.map((e) => ({ value: e, label: humanize(e) }))]}
          onChange={(value) => updateParams({ environment: value, offset: null })}
        />
        {filtered && (
          <button
            type="button"
            className="btn-ghost"
            onClick={() => {
              setTyped({ basedOn: "", value: "" });
              updateParams({ q: null, decision: null, severity: null, environment: null, offset: null });
            }}
          >
            Clear filters
          </button>
        )}
      </div>

      <Card flush>
        <DataTable
          caption="Scans"
          columns={COLUMNS}
          rows={page?.items}
          rowKey={(scan) => scan.id}
          loading={query.loading}
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
                title={filtered ? "No scans match these filters." : "No scans yet."}
                description={filtered ? "Change or clear the filters." : canScan ? "Start one with New scan." : undefined}
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
          footnote="Sorting a column reorders this page only."
        />
      </Card>
    </>
  );
}
