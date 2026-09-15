import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { ListScansParams, Page, ReportFormat, SbomFormat, Scan, ScanRequest, ScanStats, ScanSummary } from "./types";

/**
 * How long the console waits for a synchronous scan. The server analyses for up to
 * SCAN_TIMEOUT_SECONDS (180 s by default) and then stores the result; the web server's
 * proxy_read_timeout is 210 s (frontend/nginx.conf). Waiting longer than both means the client never
 * abandons a scan the server is still running: the proxy's 504 arrives first. If an operator raises
 * SCAN_TIMEOUT_SECONDS, nginx and this value have to be raised with it.
 */
export const SCAN_REQUEST_TIMEOUT_MS = 215_000;

export async function createScan(body: ScanRequest): Promise<Scan> {
  const r = await api.post<Scan>("/scans", { ecosystem: "pypi", ...body }, { timeout: SCAN_REQUEST_TIMEOUT_MS });
  return r.data;
}

export async function listScans(params: ListScansParams = {}, opts: RequestOptions = {}): Promise<Page<ScanSummary>> {
  const r = await api.get<Page<ScanSummary>>("/scans", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

export async function getScanStats(opts: RequestOptions = {}): Promise<ScanStats> {
  const r = await api.get<ScanStats>("/scans/stats/overview", { signal: opts.signal });
  return r.data;
}

export async function getScan(id: string, opts: RequestOptions = {}): Promise<Scan> {
  const r = await api.get<Scan>(`/scans/${pathSegment(id)}`, { signal: opts.signal });
  return r.data;
}

/**
 * Report export. Returned as text (JSON/SARIF are serialised JSON) so the caller can offer it as
 * a download. The HTML report must never be injected into the page; download it as a file.
 */
export async function getScanReport(id: string, format: ReportFormat, opts: RequestOptions = {}): Promise<string> {
  const r = await api.get<string>(`/scans/${pathSegment(id)}/report`, {
    params: { format },
    responseType: "text",
    transformResponse: (d: unknown) => d,
    signal: opts.signal,
  });
  return r.data;
}

export async function getScanSbom(id: string, format: SbomFormat, opts: RequestOptions = {}): Promise<string> {
  const r = await api.get<string>(`/scans/${pathSegment(id)}/sbom`, {
    params: { format },
    responseType: "text",
    transformResponse: (d: unknown) => d,
    signal: opts.signal,
  });
  return r.data;
}
