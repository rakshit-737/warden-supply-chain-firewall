import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { ContainerScan, ContainerScanListItem, Page, PageParams } from "./types";

export interface ContainerScanUpload {
  /** The output of `docker save` (or an OCI layout tarball). */
  archive: Blob;
  /** Optional label, e.g. "repo:tag". */
  imageRef?: string;
  /** Run Trivy when the server has it (default true). */
  vulnerabilities?: boolean;
}

/** Requires container:scan. Sends the archive as the raw request body. */
export async function createContainerScan(upload: ContainerScanUpload): Promise<ContainerScan> {
  const r = await api.post<ContainerScan>("/containers/scans", upload.archive, {
    headers: { "Content-Type": "application/octet-stream" },
    params: cleanParams({ image_ref: upload.imageRef || undefined, vulnerabilities: upload.vulnerabilities }),
    // Uploads and in-memory analysis of large images take longer than ordinary requests.
    timeout: 15 * 60 * 1000,
  });
  return r.data;
}

export async function listContainerScans(
  params: PageParams = {},
  opts: RequestOptions = {},
): Promise<Page<ContainerScanListItem>> {
  const r = await api.get<Page<ContainerScanListItem>>("/containers/scans", {
    params: cleanParams(params),
    signal: opts.signal,
  });
  return r.data;
}

export async function getContainerScan(id: string, opts: RequestOptions = {}): Promise<ContainerScan> {
  const r = await api.get<ContainerScan>(`/containers/scans/${pathSegment(id)}`, { signal: opts.signal });
  return r.data;
}

/** CycloneDX document listing the image packages, as text for download. */
export async function getContainerScanSbom(id: string, opts: RequestOptions = {}): Promise<string> {
  const r = await api.get<string>(`/containers/scans/${pathSegment(id)}/sbom`, {
    responseType: "text",
    transformResponse: (d: unknown) => d,
    signal: opts.signal,
  });
  return r.data;
}
