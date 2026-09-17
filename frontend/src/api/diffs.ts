import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { Page, PageParams, ReleaseDiff, ReleaseDiffCreate, ReleaseDiffListItem } from "./types";

/** Requires diff:create. Analyses both releases, so it can take as long as two scans. */
export async function createDiff(body: ReleaseDiffCreate): Promise<ReleaseDiff> {
  const r = await api.post<ReleaseDiff>("/diffs", { ecosystem: "pypi", ...body }, { timeout: 15 * 60 * 1000 });
  return r.data;
}

export async function listDiffs(
  params: PageParams & { package?: string; drift_only?: boolean } = {},
  opts: RequestOptions = {},
): Promise<Page<ReleaseDiffListItem>> {
  const r = await api.get<Page<ReleaseDiffListItem>>("/diffs", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

export async function getDiff(id: string, opts: RequestOptions = {}): Promise<ReleaseDiff> {
  const r = await api.get<ReleaseDiff>(`/diffs/${pathSegment(id)}`, { signal: opts.signal });
  return r.data;
}
