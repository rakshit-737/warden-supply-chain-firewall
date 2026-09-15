import { api, pathSegment, type RequestOptions } from "./client";
import type { Finding, GraphAnalysis, PackageOverview, Scan } from "./types";

const base = (ecosystem: string, name: string) => `/packages/${pathSegment(ecosystem)}/${pathSegment(name)}`;

/** Versions scanned, risk history and events for a package. */
export async function getPackage(ecosystem: string, name: string, opts: RequestOptions = {}): Promise<PackageOverview> {
  const r = await api.get<PackageOverview>(base(ecosystem, name), { signal: opts.signal });
  return r.data;
}

/** Latest scan of one version. */
export async function getPackageVersion(
  ecosystem: string,
  name: string,
  version: string,
  opts: RequestOptions = {},
): Promise<Scan> {
  const r = await api.get<Scan>(`${base(ecosystem, name)}/${pathSegment(version)}`, { signal: opts.signal });
  return r.data;
}

export async function getPackageFindings(
  ecosystem: string,
  name: string,
  version: string,
  opts: RequestOptions = {},
): Promise<Finding[]> {
  const r = await api.get<Finding[]>(`${base(ecosystem, name)}/${pathSegment(version)}/findings`, {
    signal: opts.signal,
  });
  return r.data;
}

/** requires_dist subgraph for one version. */
export async function getPackageGraph(
  ecosystem: string,
  name: string,
  version: string,
  opts: RequestOptions = {},
): Promise<GraphAnalysis> {
  const r = await api.get<GraphAnalysis>(`${base(ecosystem, name)}/${pathSegment(version)}/graph`, {
    signal: opts.signal,
  });
  return r.data;
}
