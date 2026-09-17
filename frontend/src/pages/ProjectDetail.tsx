import { useState, type ChangeEvent, type FormEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { toApiError, type ApiError } from "../api/client";
import { createProjectScan, getProject, listProjectScans } from "../api/projects";
import { ENVIRONMENTS, type Environment, type ProjectScanSummary } from "../api/types";
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
import { LoadingBlock } from "../components/Skeleton";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime } from "../lib/format";
import { LINK_CLASS } from "../lib/styles";

const PAGE_SIZE = 20;
/** Mirrors the server limits (backend schemas/project.py) so users learn about them before uploading. */
export const MAX_MANIFEST_FILES = 50;
export const MAX_MANIFEST_BYTES = 1_000_000;

function scanColumns(projectId: string): Column<ProjectScanSummary>[] {
  return [
    {
      id: "created",
      header: "Scanned",
      cell: (s) => (
        <Link to={`/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(s.id)}`} className={LINK_CLASS}>
          {formatDateTime(s.created_at)}
        </Link>
      ),
      sortValue: (s) => s.created_at,
    },
    { id: "decision", header: "Decision", cell: (s) => <DecisionBadge value={s.decision} /> },
    { id: "risk", header: "Risk", cell: (s) => s.risk_score, sortValue: (s) => s.risk_score, align: "right" },
    {
      id: "components",
      header: "Components",
      cell: (s) => `${s.component_count} (${s.direct_count} direct)`,
      sortValue: (s) => s.component_count,
      align: "right",
    },
    { id: "environment", header: "Environment", cell: (s) => s.environment ?? "—" },
  ];
}

interface ManifestDraft {
  path: string;
  text: string;
}

function ScanForm({ projectId, onDone }: { projectId: string; onDone: (scanId: string) => void }) {
  const [paste, setPaste] = useState("");
  const [pastePath, setPastePath] = useState("requirements.txt");
  const [uploads, setUploads] = useState<ManifestDraft[]>([]);
  const [environment, setEnvironment] = useState<Environment>("production");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  async function pickFiles(event: ChangeEvent<HTMLInputElement>) {
    setProblem(null);
    const picked = Array.from(event.target.files ?? []);
    if (picked.length > MAX_MANIFEST_FILES) {
      setProblem(`Choose at most ${MAX_MANIFEST_FILES} files.`);
      return;
    }
    const tooLarge = picked.find((f) => f.size > MAX_MANIFEST_BYTES);
    if (tooLarge) {
      setProblem(`${tooLarge.name} is larger than ${MAX_MANIFEST_BYTES.toLocaleString()} bytes.`);
      return;
    }
    const drafts = await Promise.all(
      picked.map(async (file) => ({ path: file.webkitRelativePath || file.name, text: await file.text() })),
    );
    setUploads(drafts);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const files: Record<string, string> = {};
    for (const draft of uploads) files[draft.path] = draft.text;
    if (paste.trim()) files[pastePath.trim() || "requirements.txt"] = paste;
    if (Object.keys(files).length === 0) {
      setProblem("Paste a manifest or choose manifest files first.");
      return;
    }
    setBusy(true);
    setProblem(null);
    setError(null);
    try {
      const scan = await createProjectScan(projectId, { files, environment });
      onDone(scan.id);
    } catch (err) {
      setError(toApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Scan manifests"
      description="Only the file contents are sent. Warden parses them; it never installs or runs anything."
    >
      <form onSubmit={(event) => void submit(event)} className="flex flex-col gap-4">
        <div>
          <label htmlFor="manifest-files" className="label">
            Manifest files (requirements*.txt, pyproject.toml, poetry.lock, Pipfile.lock, uv.lock, Dockerfile, compose files)
          </label>
          <input id="manifest-files" type="file" multiple className="input" onChange={(event) => void pickFiles(event)} />
          {uploads.length > 0 && (
            <p className="mt-1 text-xs text-ink-secondary">
              {uploads.length} file(s): {uploads.map((u) => u.path).join(", ")}
            </p>
          )}
        </div>
        <div className="grid gap-4 sm:grid-cols-[14rem_minmax(0,1fr)]">
          <div>
            <label htmlFor="paste-path" className="label">
              Pasted file name
            </label>
            <input id="paste-path" className="input font-mono" value={pastePath} onChange={(e) => setPastePath(e.target.value)} />
          </div>
          <div>
            <label htmlFor="paste-content" className="label">
              Or paste a manifest
            </label>
            <textarea
              id="paste-content"
              className="input min-h-28 font-mono"
              value={paste}
              maxLength={MAX_MANIFEST_BYTES}
              onChange={(e) => setPaste(e.target.value)}
            />
          </div>
        </div>
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label htmlFor="scan-environment" className="label">
              Environment
            </label>
            <select
              id="scan-environment"
              className="input"
              value={environment}
              onChange={(e) => setEnvironment(e.target.value as Environment)}
            >
              {ENVIRONMENTS.map((env) => (
                <option key={env} value={env}>
                  {env}
                </option>
              ))}
            </select>
          </div>
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? "Scanning…" : "Scan"}
          </button>
        </div>
        {problem && <FormAlert>{problem}</FormAlert>}
        {error && <ErrorState error={error} title="The project scan did not complete" />}
      </form>
    </Card>
  );
}

function ProjectDetailView() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const canWrite = usePermission(PERMISSIONS.PROJECT_WRITE);
  const [searchParams, setSearchParams] = useSearchParams();
  const offset = Math.max(0, Number.parseInt(searchParams.get("offset") ?? "0", 10) || 0);
  const project = useApiQuery(`project:${id}`, (signal) => getProject(id, { signal }));
  const scans = useApiQuery(`project-scans:${id}:${offset}`, (signal) =>
    listProjectScans(id, { limit: PAGE_SIZE, offset }, { signal }),
  );
  const page = scans.data ?? scans.previousData;

  if (project.error) {
    return (
      <>
        <PageHeader title="Project" back={{ to: "/projects", label: "Projects" }} />
        <ErrorState error={project.error} title="This project could not be loaded" onRetry={project.reload} />
      </>
    );
  }
  if (!project.data) return <LoadingBlock label="Loading project" />;

  return (
    <>
      <PageHeader
        title={project.data.name}
        back={{ to: "/projects", label: "Projects" }}
        description={project.data.description || undefined}
      />
      <div className="flex flex-col gap-4">
        {canWrite && (
          <ScanForm
            projectId={id}
            onDone={(scanId) => void navigate(`/projects/${encodeURIComponent(id)}/scans/${encodeURIComponent(scanId)}`)}
          />
        )}
        <DataTable
          caption="Scan history"
          showCaption
          columns={scanColumns(id)}
          rows={page?.items}
          rowKey={(s) => s.id}
          loading={scans.loading}
          error={scans.error}
          onRetry={scans.reload}
          empty={<EmptyState title="This project has not been scanned yet." compact />}
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

export default function ProjectDetail() {
  return (
    <RequirePermission permission={PERMISSIONS.PROJECT_READ}>
      <ProjectDetailView />
    </RequirePermission>
  );
}
