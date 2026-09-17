import { api, pathSegment, type RequestOptions } from "./client";
import type { PackageOverview } from "./types";

/** Stored verdicts, advisories, monitoring state and release diffs for one package. */
export async function getPackage(ecosystem: string, name: string, opts: RequestOptions = {}): Promise<PackageOverview> {
  const r = await api.get<PackageOverview>(`/packages/${pathSegment(ecosystem)}/${pathSegment(name)}`, {
    signal: opts.signal,
  });
  return r.data;
}
