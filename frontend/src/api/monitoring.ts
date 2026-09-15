import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { MonitoredPackage, MonitoredPackageCreate, MonitoringStatus, Page, PageParams } from "./types";

export async function listMonitoredPackages(
  params: PageParams = {},
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
export async function removeMonitoredPackage(id: string): Promise<void> {
  await api.delete(`/monitoring/packages/${pathSegment(id)}`);
}

/** Requires monitor:write. Triggers a monitoring pass for packages that are due. */
export async function runMonitoring(): Promise<MonitoringStatus> {
  const r = await api.post<MonitoringStatus>("/monitoring/run");
  return r.data;
}

export async function getMonitoringStatus(opts: RequestOptions = {}): Promise<MonitoringStatus> {
  const r = await api.get<MonitoringStatus>("/monitoring/status", { signal: opts.signal });
  return r.data;
}
