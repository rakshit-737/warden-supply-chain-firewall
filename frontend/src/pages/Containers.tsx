import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { toApiError, type ApiError } from "../api/client";
import { createContainerScan, listContainerScans } from "../api/containers";
import type { ContainerScanListItem } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DataTable, type Column } from "../components/DataTable";
import { DecisionBadge } from "../components/DecisionBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { FormAlert } from "../components/FormAlert";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime } from "../lib/format";
import { LINK_CLASS } from "../lib/styles";

const PAGE_SIZE = 25;
/** Server default (backend MAX_IMAGE_UPLOAD_BYTES); the server enforces its own configured value. */
export const MAX_IMAGE_BYTES = 256 * 1024 * 1024;

const COLUMNS: Column<ContainerScanListItem>[] = [
  {
    id: "image",
    header: "Image",
    cell: (c) => (
      <Link to={`/containers/${encodeURIComponent(c.id)}`} className={`${LINK_CLASS} font-mono text-[0.8125rem]`}>
        {c.image_ref}
      </Link>
    ),
    sortValue: (c) => c.image_ref,
  },
  { id: "decision", header: "Decision", cell: (c) => <DecisionBadge value={c.decision} /> },
  { id: "risk", header: "Risk", cell: (c) => c.risk_score ?? "—", sortValue: (c) => c.risk_score, align: "right" },
  {
    id: "status",
    header: "Analysis",
    cell: (c) => (c.status === "completed" ? "Complete" : "Incomplete"),
    sortValue: (c) => c.status,
  },
  { id: "created", header: "Scanned", cell: (c) => formatDateTime(c.created_at), sortValue: (c) => c.created_at },
];

function UploadForm() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [imageRef, setImageRef] = useState("");
  const [vulnerabilities, setVulnerabilities] = useState(true);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || busy) return;
    if (file.size > MAX_IMAGE_BYTES) {
      setProblem(`The archive is larger than ${Math.round(MAX_IMAGE_BYTES / 1024 / 1024)} MiB.`);
      return;
    }
    setBusy(true);
    setProblem(null);
    setError(null);
    try {
      const scan = await createContainerScan({ archive: file, imageRef: imageRef.trim(), vulnerabilities });
      void navigate(`/containers/${encodeURIComponent(scan.id)}`);
    } catch (err) {
      setError(toApiError(err));
      setBusy(false);
    }
  }

  return (
    <Card
      title="Scan an image archive"
      description={
        <>
          Upload the output of <code className="font-mono">docker save IMAGE -o image.tar</code>. The image is
          analysed offline and never run.
        </>
      }
    >
      <form onSubmit={(event) => void submit(event)} className="flex flex-col gap-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="image-archive" className="label">
              Image archive (.tar)
            </label>
            <input
              id="image-archive"
              type="file"
              accept=".tar,application/x-tar"
              className="input"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>
          <div>
            <label htmlFor="image-ref" className="label">
              Label (optional)
            </label>
            <input
              id="image-ref"
              className="input font-mono"
              placeholder="registry/app:1.2.3"
              value={imageRef}
              maxLength={512}
              onChange={(e) => setImageRef(e.target.value)}
            />
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={vulnerabilities} onChange={(e) => setVulnerabilities(e.target.checked)} />
          Check known vulnerabilities with Trivy (when the server has it installed)
        </label>
        <div>
          <button type="submit" className="btn-primary" disabled={!file || busy}>
            {busy ? "Uploading and analysing…" : "Scan image"}
          </button>
        </div>
        {problem && <FormAlert>{problem}</FormAlert>}
        {error && <ErrorState error={error} title="The image scan did not complete" />}
      </form>
    </Card>
  );
}

function ContainersView() {
  const canScan = usePermission(PERMISSIONS.CONTAINER_SCAN);
  const [searchParams, setSearchParams] = useSearchParams();
  const offset = Math.max(0, Number.parseInt(searchParams.get("offset") ?? "0", 10) || 0);
  const query = useApiQuery(`containers:${offset}`, (signal) =>
    listContainerScans({ limit: PAGE_SIZE, offset }, { signal }),
  );
  const page = query.data ?? query.previousData;

  return (
    <>
      <PageHeader
        title="Containers"
        description="Image configuration, installed packages, secrets and known vulnerabilities of container images."
      />
      <div className="flex flex-col gap-4">
        {canScan && <UploadForm />}
        <DataTable
          caption="Container scans"
          columns={COLUMNS}
          rows={page?.items}
          rowKey={(c) => c.id}
          loading={query.loading}
          error={query.error}
          onRetry={query.reload}
          empty={<EmptyState title="No images have been scanned yet." />}
          pagination={
            page
              ? {
                  total: page.total,
                  limit: page.limit,
                  offset: page.offset,
                  onOffsetChange: (next) => setSearchParams(next ? { offset: String(next) } : {}),
                }
              : undefined
          }
        />
      </div>
    </>
  );
}

export default function Containers() {
  return (
    <RequirePermission permission={PERMISSIONS.SCAN_READ}>
      <ContainersView />
    </RequirePermission>
  );
}
