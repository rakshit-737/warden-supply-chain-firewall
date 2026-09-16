import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type {
  ExceptionTransition,
  ListExceptionsParams,
  Page,
  PolicyException,
  PolicyExceptionCreate,
} from "./types";

/** Requires policy:read. Newest first; paginated (limit at most 200). */
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

export const EXCEPTION_ACTIONS = ["approve", "reject", "revoke"] as const;
export type ExceptionAction = (typeof EXCEPTION_ACTIONS)[number];

function transitionBody(comment?: string): ExceptionTransition | undefined {
  const trimmed = comment?.trim();
  return trimmed ? { comment: trimmed } : undefined;
}

/**
 * POST /policies/exceptions/{id}/{action}.
 *
 * - approve / reject require exception:approve, and the server enforces separation of duties: the
 *   requester can never decide their own request, whatever their role (403, code "separation_of_duties").
 * - revoke: an approver may revoke any open exception; a requester may withdraw their own.
 * - A request that is no longer pending (or open, for revoke), has expired, or changed concurrently is
 *   refused with 409.
 */
export async function transitionException(
  id: string,
  action: ExceptionAction,
  comment?: string,
): Promise<PolicyException> {
  const r = await api.post<PolicyException>(
    `/policies/exceptions/${pathSegment(id)}/${action}`,
    transitionBody(comment),
  );
  return r.data;
}

export function approveException(id: string, comment?: string): Promise<PolicyException> {
  return transitionException(id, "approve", comment);
}

export function rejectException(id: string, comment?: string): Promise<PolicyException> {
  return transitionException(id, "reject", comment);
}

export function revokeException(id: string, comment?: string): Promise<PolicyException> {
  return transitionException(id, "revoke", comment);
}
