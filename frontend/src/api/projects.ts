import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type {
  GraphAnalysis,
  Page,
  PageParams,
  Project,
  ProjectComponent,
  ProjectCreate,
  ProjectScan,
  ProjectScanCreate,
  ProjectScanSummary,
  SbomFormat,
} from "./types";

const scanBase = (projectId: string, scanId: string) =>
  `/projects/${pathSegment(projectId)}/scans/${pathSegment(scanId)}`;

/** Requires project:write. */
export async function createProject(body: ProjectCreate): Promise<Project> {
  const r = await api.post<Project>("/projects", body);
  return r.data;
}

export async function listProjects(params: PageParams = {}, opts: RequestOptions = {}): Promise<Page<Project>> {
  const r = await api.get<Page<Project>>("/projects", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

export async function getProject(id: string, opts: RequestOptions = {}): Promise<Project> {
  const r = await api.get<Project>(`/projects/${pathSegment(id)}`, { signal: opts.signal });
  return r.data;
}

/** Requires project:write. Submits manifest contents only (never a server path); the server caps sizes. */
export async function createProjectScan(projectId: string, body: ProjectScanCreate): Promise<ProjectScan> {
  const r = await api.post<ProjectScan>(`/projects/${pathSegment(projectId)}/scans`, body);
  return r.data;
}

export async function listProjectScans(
  projectId: string,
  params: PageParams = {},
  opts: RequestOptions = {},
): Promise<Page<ProjectScanSummary>> {
  const r = await api.get<Page<ProjectScanSummary>>(`/projects/${pathSegment(projectId)}/scans`, {
    params: cleanParams(params),
    signal: opts.signal,
  });
  return r.data;
}

export async function getProjectScan(projectId: string, scanId: string, opts: RequestOptions = {}): Promise<ProjectScan> {
  const r = await api.get<ProjectScan>(scanBase(projectId, scanId), { signal: opts.signal });
  return r.data;
}

export async function listProjectScanComponents(
  projectId: string,
  scanId: string,
  params: PageParams & { direct?: boolean } = {},
  opts: RequestOptions = {},
): Promise<Page<ProjectComponent>> {
  const r = await api.get<Page<ProjectComponent>>(`${scanBase(projectId, scanId)}/components`, {
    params: cleanParams(params),
    signal: opts.signal,
  });
  return r.data;
}

export async function getProjectScanGraph(projectId: string, scanId: string, opts: RequestOptions = {}): Promise<GraphAnalysis> {
  const r = await api.get<GraphAnalysis>(`${scanBase(projectId, scanId)}/graph`, { signal: opts.signal });
  return r.data;
}

/** SBOM document as text (CycloneDX 1.6 or SPDX 2.3 JSON), for download. */
export async function getProjectScanSbom(
  projectId: string,
  scanId: string,
  format: SbomFormat,
  opts: RequestOptions = {},
): Promise<string> {
  const r = await api.get<string>(`${scanBase(projectId, scanId)}/sbom`, {
    params: { format },
    responseType: "text",
    transformResponse: (d: unknown) => d,
    signal: opts.signal,
  });
  return r.data;
}
