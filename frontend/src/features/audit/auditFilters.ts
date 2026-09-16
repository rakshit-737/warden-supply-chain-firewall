import type { ListAuditParams } from "../../api/types";
import { isUuid, parseOffset } from "../events/searchParams";

/** Actions the backend records today (audit.record call sites); suggestions only, any value can be searched. */
export const KNOWN_AUDIT_ACTIONS = [
  "auth.refresh_reuse_detected",
  "event.ack",
  "exception.approve",
  "exception.reject",
  "exception.request",
  "exception.revoke",
  "policy.activate",
  "policy.create",
  "policy.update",
  "scan.create",
  "user.login",
  "user.login_failed",
  "user.logout",
  "user.register",
  "user.update",
] as const;

/** Target types the backend records today; suggestions only. */
export const KNOWN_AUDIT_TARGET_TYPES = ["package", "policy", "policy_exception", "security_event", "user"] as const;

/** Server bounds (backend routers/audit.py). */
export const MAX_ACTION_LENGTH = 80;
export const MAX_TARGET_TYPE_LENGTH = 40;

export type AuditFilterParam = "action" | "actor_id" | "target_type" | "offset";

export const AUDIT_FILTER_LABEL: Record<AuditFilterParam, string> = {
  action: "action",
  actor_id: "actor ID",
  target_type: "target type",
  offset: "page",
};

export interface AuditFilters {
  action?: string;
  actorId?: string;
  targetType?: string;
}

export interface AuditQueryState {
  filters: AuditFilters;
  offset: number;
  /** Parameters present in the address but not valid, so not sent to the server. */
  ignored: AuditFilterParam[];
}

export function readAuditQuery(params: URLSearchParams): AuditQueryState {
  const ignored: AuditFilterParam[] = [];
  const filters: AuditFilters = {};
  const present = (name: AuditFilterParam): string | null => {
    const raw = params.get(name);
    return raw === null || raw.trim() === "" ? null : raw.trim();
  };

  const action = present("action");
  if (action !== null) {
    if (action.length <= MAX_ACTION_LENGTH) filters.action = action;
    else ignored.push("action");
  }
  const actor = present("actor_id");
  if (actor !== null) {
    if (isUuid(actor)) filters.actorId = actor.toLowerCase();
    else ignored.push("actor_id");
  }
  const targetType = present("target_type");
  if (targetType !== null) {
    if (targetType.length <= MAX_TARGET_TYPE_LENGTH) filters.targetType = targetType;
    else ignored.push("target_type");
  }
  let offset = parseOffset(params.get("offset"));
  if (offset === null) {
    ignored.push("offset");
    offset = 0;
  }
  return { filters, offset, ignored };
}

export function hasActiveAuditFilters(filters: AuditFilters): boolean {
  return Object.values(filters).some((value) => value !== undefined);
}

export function toListAuditParams(filters: AuditFilters, offset: number, limit: number): ListAuditParams {
  return { limit, offset, action: filters.action, actor_id: filters.actorId, target_type: filters.targetType };
}

export interface AuditFilterDraft {
  action: string;
  actorId: string;
  targetType: string;
}

export type AuditFilterErrors = Partial<Record<keyof AuditFilterDraft, string>>;

export interface AuditFilterValues {
  action: string | null;
  actorId: string | null;
  targetType: string | null;
}

export function validateAuditFilters(draft: AuditFilterDraft): { errors: AuditFilterErrors; values: AuditFilterValues } {
  const errors: AuditFilterErrors = {};
  const action = draft.action.trim();
  const actor = draft.actorId.trim();
  const targetType = draft.targetType.trim();
  if (action.length > MAX_ACTION_LENGTH) errors.action = `Actions are at most ${MAX_ACTION_LENGTH} characters.`;
  if (actor !== "" && !isUuid(actor)) {
    errors.actorId = "Enter the actor's user ID as a UUID, for example 3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b.";
  }
  if (targetType.length > MAX_TARGET_TYPE_LENGTH) {
    errors.targetType = `Target types are at most ${MAX_TARGET_TYPE_LENGTH} characters.`;
  }
  return {
    errors,
    values: { action: action || null, actorId: actor ? actor.toLowerCase() : null, targetType: targetType || null },
  };
}

/** First characters of a long identifier, for tables; the full value is shown in the detail view. */
export function shortId(id: string, length = 8): string {
  return id.length > length + 3 ? `${id.slice(0, length)}…` : id;
}
