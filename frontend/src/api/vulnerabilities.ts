import { api, pathSegment, type RequestOptions } from "./client";
import type { Page, Vulnerability, VulnerabilityQuery } from "./types";

/** Requires vuln:read. */
export async function listVulnerabilities(query: VulnerabilityQuery, opts: RequestOptions = {}): Promise<Page<Vulnerability>> {
  const r = await api.get<Page<Vulnerability>>("/vulnerabilities", { params: query, signal: opts.signal });
  return r.data;
}

/** Requires vuln:read. `id` is an OSV id (e.g. PYSEC-..., GHSA-...). */
export async function getVulnerability(id: string, opts: RequestOptions = {}): Promise<Vulnerability> {
  const r = await api.get<Vulnerability>(`/vulnerabilities/${pathSegment(id)}`, { signal: opts.signal });
  return r.data;
}
