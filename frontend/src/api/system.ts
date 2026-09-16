import { api, type RequestOptions } from "./client";
import type { SystemInfo, ToolStatus } from "./types";

/**
 * Requires system:read. Whether the optional external analysis tools (yara, semgrep, gitleaks, syft,
 * grype, trivy) are installed on the API process that answers. The server caches probes per process.
 */
export async function getSystemTools(opts: RequestOptions = {}): Promise<ToolStatus[]> {
  const r = await api.get<ToolStatus[]>("/system/tools", { signal: opts.signal });
  return r.data;
}

/** Requires system:read. Versions, feature switches and limits; never secrets, connection strings or paths. */
export async function getSystemInfo(opts: RequestOptions = {}): Promise<SystemInfo> {
  const r = await api.get<SystemInfo>("/system/info", { signal: opts.signal });
  return r.data;
}
