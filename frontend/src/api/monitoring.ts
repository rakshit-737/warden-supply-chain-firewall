import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type {
  MonitoredPackage,
  MonitoredPackageCreate,
  MonitoredPackageUpdate,
  MonitoringCheckResult,
  Page,
  PageParams,
} from "./types";

export async function listMonitoredPackages(
  params: PageParams & { failing?: boolean } = {},
  opts: RequestOptions = {},
): Promise<Page<MonitoredPackage>> {
  const r = await api.get<Page<MonitoredPackage>>("/monitoring/packages", {
    params: cleanParams(params),
    signal: opts.signal,
  });
  return r.data;
}

/** Requires monitor:write. */
export async function addMonitoredPackage(body: MonitoredPackageCreate): Promise<MonitoredPackage> {
  const r = await api.post<MonitoredPackage>("/monitoring/packages", { ecosystem: "pypi", ...body });
  return r.data;
}

/** Requires monitor:write. */
export async function updateMonitoredPackage(id: string, body: MonitoredPackageUpdate): Promise<MonitoredPackage> {
  const r = await api.patch<MonitoredPackage>(`/monitoring/packages/${pathSegment(id)}`, body);
  return r.data;
}

/** Requires monitor:write. */
export async function removeMonitoredPackage(id: string): Promise<void> {
  await api.delete(`/monitoring/packages/${pathSegment(id)}`);
}

/** Requires monitor:write. Runs one check now (registry lookup and, for a new release, analysis). */
export async function checkMonitoredPackage(id: string): Promise<MonitoringCheckResult> {
  const r = await api.post<MonitoringCheckResult>(`/monitoring/packages/${pathSegment(id)}/check`, undefined, {
    timeout: 10 * 60 * 1000,
  });
  return r.data;
}
