import { api, cleanParams, type RequestOptions } from "./client";
import type { AuditEvent, AuditVerifyResult, ListAuditParams, Page } from "./types";

/** Requires audit:read. */
export async function listAuditEvents(params: ListAuditParams = {}, opts: RequestOptions = {}): Promise<Page<AuditEvent>> {
  const r = await api.get<Page<AuditEvent>>("/audit", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

/** Requires audit:read. Walks the audit hash chain on the server. */
export async function verifyAuditChain(opts: RequestOptions = {}): Promise<AuditVerifyResult> {
  const r = await api.get<AuditVerifyResult>("/audit/verify", { signal: opts.signal });
  return r.data;
}
