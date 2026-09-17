import { useState } from "react";
import { useParams } from "react-router";
import { toApiError, type ApiError } from "../api/client";
import { getContainerScan, getContainerScanSbom } from "../api/containers";
import { PERMISSIONS } from "../auth/permissions";
import { Card } from "../components/Card";
import { DecisionBadge } from "../components/DecisionBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { FindingCard } from "../components/FindingCard";
import { KeyValueList } from "../components/KeyValueList";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { LoadingBlock } from "../components/Skeleton";
import { useApiQuery } from "../hooks/useApiQuery";
import { downloadText, safeFileName } from "../lib/download";
import { formatDateTime } from "../lib/format";

const SCAN_STATUS_TEXT: Record<string, string> = {
  ok: "Completed",
  unavailable: "Not assessed: Trivy is not installed on the server",
  error: "Not assessed: Trivy failed",
  timeout: "Not assessed: Trivy timed out",
  skipped: "Not assessed",
};

function SbomButton({ id, name }: { id: string; name: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  async function download() {
    setBusy(true);
    setError(null);
    try {
      downloadText(safeFileName(`${name}-cyclonedx`, "json"), await getContainerScanSbom(id));
    } catch (err) {
      setError(toApiError(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex flex-col items-end gap-2">
      <button type="button" className="btn-secondary" disabled={busy} onClick={() => void download()}>
        {busy ? "Preparing…" : "CycloneDX SBOM"}
      </button>
      {error && <ErrorState error={error} title="The SBOM could not be exported" />}
    </div>
  );
}

function ContainerDetailView() {
  const { id = "" } = useParams();
  const query = useApiQuery(`container:${id}`, (signal) => getContainerScan(id, { signal }));
  const back = { to: "/containers", label: "Containers" };

  if (query.error) {
    return (
      <>
        <PageHeader title="Container scan" back={back} />
        <ErrorState error={query.error} title="This container scan could not be loaded" onRetry={query.reload} />
      </>
    );
  }
  const scan = query.data;
  if (!scan) return <LoadingBlock label="Loading container scan" />;
  const summary = scan.summary ?? {};
  const trivy = scan.tools?.trivy;
  const findings = scan.findings ?? [];
  const counts = Object.entries(summary.component_counts ?? {})
    .map(([type, count]) => `${type} ${count}`)
    .join(", ");

  return (
    <>
      <PageHeader
        title={scan.image_ref}
        heading={<span className="break-all font-mono">{scan.image_ref}</span>}
        back={back}
        meta={formatDateTime(scan.created_at)}
        actions={<SbomButton id={scan.id} name={scan.image_ref} />}
      />
      <div className="flex flex-col gap-4">
        {scan.status !== "completed" && (
          <Card title="Analysis incomplete">
            <p className="text-sm">
              Part of this image could not be read, so the result does not cover the whole image. Treat it as unverified.
            </p>
          </Card>
        )}
        <Card>
          <div className="flex flex-wrap items-start gap-6">
            <DecisionBadge value={scan.decision} size="lg" />
            <KeyValueList
              columns={2}
              items={[
                { term: "Risk score", value: scan.risk_score },
                { term: "Config digest", value: scan.image_digest, mono: true },
                { term: "Platform", value: [summary.os, summary.architecture].filter(Boolean).join("/") },
                { term: "User", value: summary.user || "root (not set)" },
                { term: "Layers", value: summary.layer_count },
                { term: "Exposed ports", value: (summary.exposed_ports ?? []).join(", ") },
                { term: "Packages", value: counts || "None found" },
                { term: "Known vulnerabilities", value: trivy ? SCAN_STATUS_TEXT[trivy.status] ?? trivy.status : "Not assessed" },
              ]}
            />
          </div>
        </Card>
        {(summary.reasons ?? []).length > 0 && (
          <Card title="Why this decision">
            <ul className="list-disc pl-5 text-sm">
              {(summary.reasons ?? []).map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </Card>
        )}
        <Card title={`Findings (${findings.length})`}>
          {findings.length ? (
            <div className="flex flex-col gap-2">
              {findings.map((f, index) => (
                <FindingCard key={f.finding_id ?? `${f.code}-${index}`} finding={f} />
              ))}
            </div>
          ) : (
            <EmptyState title="No findings were reported." description="That is not proof the image is safe." compact />
          )}
        </Card>
        {(summary.warnings ?? []).length > 0 && (
          <Card title="Analysis warnings">
            <ul className="list-disc pl-5 text-sm">
              {(summary.warnings ?? []).map((w) => (
                <li key={w} className="wrap-break-word">
                  {w}
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>
    </>
  );
}

export default function ContainerDetail() {
  return (
    <RequirePermission permission={PERMISSIONS.SCAN_READ}>
      <ContainerDetailView />
    </RequirePermission>
  );
}
