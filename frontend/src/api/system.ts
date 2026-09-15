import { api, type RequestOptions } from "./client";
import type { SystemInfo, ToolStatus } from "./types";

/** Requires system:read. Availability of external analysis tools (yara, semgrep, syft, ...). */
export async function getSystemTools(opts: RequestOptions = {}): Promise<ToolStatus[]> {
  const r = await api.get<ToolStatus[]>("/system/tools", { signal: opts.signal });
  return r.data;
}

/** Requires system:read. */
export async function getSystemInfo(opts: RequestOptions = {}): Promise<SystemInfo> {
  const r = await api.get<SystemInfo>("/system/info", { signal: opts.signal });
  return r.data;
}
