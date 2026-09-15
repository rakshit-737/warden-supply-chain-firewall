import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type {
  ExceptionTransition,
  ListExceptionsParams,
  Page,
  PolicyException,
  PolicyExceptionCreate,
} from "./types";

export async function listExceptions(
  params: ListExceptionsParams = {},
  opts: RequestOptions = {},
): Promise<Page<PolicyException>> {
  const r = await api.get<Page<PolicyException>>("/policies/exceptions", {
    params: cleanParams(params),
    signal: opts.signal,
  });
  return r.data;
}

/** Requires exception:request. The request starts as `pending`. */
export async function requestException(body: PolicyExceptionCreate): Promise<PolicyException> {
  const r = await api.post<PolicyException>("/policies/exceptions", body);
  return r.data;
}

function transitionBody(comment?: string): ExceptionTransition | undefined {
  const trimmed = comment?.trim();
  return trimmed ? { comment: trimmed } : undefined;
}

/**
 * Requires exception:approve. The server also enforces separation of duties: the approver
 * must not be the requester, whatever their role.
 */
export async function approveException(id: string, comment?: string): Promise<PolicyException> {
  const r = await api.post<PolicyException>(
    `/policies/exceptions/${pathSegment(id)}/approve`,
    transitionBody(comment),
  );
  return r.data;
}

/** Requires exception:approve; the requester can never reject their own request. */
export async function rejectException(id: string, comment?: string): Promise<PolicyException> {
  const r = await api.post<PolicyException>(
    `/policies/exceptions/${pathSegment(id)}/reject`,
    transitionBody(comment),
  );
  return r.data;
}

/** An approver may revoke any open exception; a requester may withdraw their own. */
export async function revokeException(id: string, comment?: string): Promise<PolicyException> {
  const r = await api.post<PolicyException>(
    `/policies/exceptions/${pathSegment(id)}/revoke`,
    transitionBody(comment),
  );
  return r.data;
}
