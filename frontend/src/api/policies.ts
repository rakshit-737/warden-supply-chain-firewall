import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { Environment, Policy, PolicyDocument, PolicyValidationResult, PolicyWrite } from "./types";

/** Returns a plain array (not a Page), newest first. */
export async function listPolicies(
  params: { environment?: Environment } = {},
  opts: RequestOptions = {},
): Promise<Policy[]> {
  const r = await api.get<Policy[]>("/policies", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

/** The active policy of one environment (the server defaults to production). */
export async function getActivePolicy(environment?: Environment, opts: RequestOptions = {}): Promise<Policy> {
  const r = await api.get<Policy>("/policies/active", {
    params: cleanParams({ environment }),
    signal: opts.signal,
  });
  return r.data;
}

export async function createPolicy(body: PolicyWrite): Promise<Policy> {
  const r = await api.post<Policy>("/policies", body);
  return r.data;
}

export async function updatePolicy(id: string, body: PolicyWrite): Promise<Policy> {
  const r = await api.put<Policy>(`/policies/${pathSegment(id)}`, body);
  return r.data;
}

export async function activatePolicy(id: string): Promise<Policy> {
  const r = await api.post<Policy>(`/policies/${pathSegment(id)}/activate`);
  return r.data;
}

/**
 * Validate a policy-as-code document without saving it (SPEC section 13). The request body
 * shape is this client's proposal; confirm it against the server's OpenAPI schema before use.
 */
export async function validatePolicy(document: PolicyDocument | string): Promise<PolicyValidationResult> {
  const body = typeof document === "string" ? { source: document } : { document };
  const r = await api.post<PolicyValidationResult>("/policies/validate", body);
  return r.data;
}
