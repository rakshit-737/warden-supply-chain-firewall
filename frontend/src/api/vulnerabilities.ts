import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { Vulnerability, VulnerabilityList, VulnerabilityListQuery } from "./types";

/** Requires vuln:read. Advisories found in stored verdicts. */
export async function listVulnerabilities(
  query: VulnerabilityListQuery = {},
  opts: RequestOptions = {},
): Promise<VulnerabilityList> {
  const r = await api.get<VulnerabilityList>("/vulnerabilities", { params: cleanParams(query), signal: opts.signal });
  return r.data;
}

/** Requires vuln:read. One advisory from the server's local cache (populated by lookups). */
export async function getVulnerability(id: string, opts: RequestOptions = {}): Promise<Partial<Vulnerability> & { id: string }> {
  const r = await api.get<Partial<Vulnerability> & { id: string }>(`/vulnerabilities/${pathSegment(id)}`, {
    signal: opts.signal,
  });
  return r.data;
}
