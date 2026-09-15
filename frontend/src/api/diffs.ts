import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { Page, PageParams, ReleaseDiff, ReleaseDiffCreate } from "./types";

/** Requires diff:create. Compares the behaviour of two releases of one package. */
export async function createDiff(body: ReleaseDiffCreate): Promise<ReleaseDiff> {
  const r = await api.post<ReleaseDiff>("/diffs", body);
  return r.data;
}

export async function listDiffs(params: PageParams = {}, opts: RequestOptions = {}): Promise<Page<ReleaseDiff>> {
  const r = await api.get<Page<ReleaseDiff>>("/diffs", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

export async function getDiff(id: string, opts: RequestOptions = {}): Promise<ReleaseDiff> {
  const r = await api.get<ReleaseDiff>(`/diffs/${pathSegment(id)}`, { signal: opts.signal });
  return r.data;
}
