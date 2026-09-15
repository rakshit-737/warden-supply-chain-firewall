import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { ContainerScan, ContainerScanCreate, Page, PageParams } from "./types";

/** Requires container:scan. Send exactly one of image_ref, dockerfile content or compose content. */
export async function createContainerScan(body: ContainerScanCreate): Promise<ContainerScan> {
  const r = await api.post<ContainerScan>("/containers/scans", body);
  return r.data;
}

export async function listContainerScans(params: PageParams = {}, opts: RequestOptions = {}): Promise<Page<ContainerScan>> {
  const r = await api.get<Page<ContainerScan>>("/containers/scans", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

export async function getContainerScan(id: string, opts: RequestOptions = {}): Promise<ContainerScan> {
  const r = await api.get<ContainerScan>(`/containers/scans/${pathSegment(id)}`, { signal: opts.signal });
  return r.data;
}
