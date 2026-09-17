import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { toApiError, type ApiError } from "../api/client";
import { createProject, listProjects } from "../api/projects";
import type { Project } from "../api/types";
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

const PAGE_SIZE = 25;

const COLUMNS: Column<Project>[] = [
  {
    id: "name",
    header: "Project",
    cell: (p) => (
      <Link to={`/projects/${encodeURIComponent(p.id)}`} className={LINK_CLASS}>
        {p.name}
      </Link>
    ),
    sortValue: (p) => p.name.toLowerCase(),
  },
  { id: "description", header: "Description", cell: (p) => <span className="break-words">{p.description || "—"}</span> },
  {
    id: "updated",
    header: "Last scanned",
    cell: (p) => (p.updated_at ? formatDateTime(p.updated_at) : "Never"),
    sortValue: (p) => p.updated_at ?? "",
  },
];

function CreateProjectForm() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const project = await createProject({ name: name.trim(), description: description.trim() || null });
      void navigate(`/projects/${encodeURIComponent(project.id)}`);
    } catch (err) {
      setError(toApiError(err));
      setBusy(false);
    }
  }

  return (
    <Card title="New project" description="A project groups the dependency manifests of one application.">
      <form onSubmit={(event) => void submit(event)} className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] sm:items-end">
        <div>
          <label htmlFor="project-name" className="label">
            Name
          </label>
          <input
            id="project-name"
            className="input"
            value={name}
            maxLength={120}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>
        <div>
          <label htmlFor="project-description" className="label">
            Description (optional)
          </label>
          <input
            id="project-description"
            className="input"
            value={description}
            maxLength={2000}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <button type="submit" className="btn-primary" disabled={busy || !name.trim()}>
          {busy ? "Creating…" : "Create project"}
        </button>
      </form>
      {error && (
        <div className="mt-3">
          <ErrorState error={error} title="The project was not created" />
        </div>
      )}
    </Card>
  );
}

function ProjectsView() {
  const canWrite = usePermission(PERMISSIONS.PROJECT_WRITE);
  const [searchParams, setSearchParams] = useSearchParams();
  const offset = Math.max(0, Number.parseInt(searchParams.get("offset") ?? "0", 10) || 0);
  const query = useApiQuery(`projects:${offset}`, (signal) => listProjects({ limit: PAGE_SIZE, offset }, { signal }));
  const page = query.data ?? query.previousData;

  return (
    <>
      <PageHeader
        title="Projects"
        description="Scan an application's dependency manifests for hygiene and dependency-confusion risks, and export its SBOM."
      />
      <div className="flex flex-col gap-4">
        {canWrite && <CreateProjectForm />}
        <DataTable
          caption="Projects"
          columns={COLUMNS}
          rows={page?.items}
          rowKey={(p) => p.id}
          loading={query.loading}
          error={query.error}
          onRetry={query.reload}
          empty={
            <EmptyState
              title="No projects yet."
              description={canWrite ? "Create one above, then submit its manifests." : "Projects appear here once an engineer creates one."}
            />
          }
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

export default function Projects() {
  return (
    <RequirePermission permission={PERMISSIONS.PROJECT_READ}>
      <ProjectsView />
    </RequirePermission>
  );
}
