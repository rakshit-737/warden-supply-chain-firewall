import { api, cleanParams, type RequestOptions } from "./client";
import type { AuditEvent, AuditVerifyResult, ListAuditParams, Page } from "./types";

/** Requires audit:read. Ordered by seq, newest first. */
export async function listAuditEvents(params: ListAuditParams = {}, opts: RequestOptions = {}): Promise<Page<AuditEvent>> {
  const r = await api.get<Page<AuditEvent>>("/audit", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

/** Requires audit:read. The server recomputes every hash of the chain, so this can take a while. */
export async function verifyAuditChain(opts: RequestOptions = {}): Promise<AuditVerifyResult> {
  const r = await api.get<AuditVerifyResult>("/audit/verify", { signal: opts.signal });
  return r.data;
}
