import { USER_ROLES, type UserRole } from "../api/types";

/**
 * UI mirror of the Warden RBAC matrix (SPEC section 6; backend app/core/permissions.py).
 *
 * This module is a UI affordance ONLY: it decides which controls to show, hide or disable so
 * people are not offered actions that will be refused. The server enforces RBAC on every
 * request; hiding a control here is never the security boundary, and a missing or stale entry
 * here cannot grant anything.
 *
 * Deny by default: an unknown role holds no permissions.
 */

export const PERMISSIONS = {
  SCAN_CREATE: "scan:create",
  PROJECT_WRITE: "project:write",
  CONTAINER_SCAN: "container:scan",
  DIFF_CREATE: "diff:create",
  SCAN_READ: "scan:read",
  PROJECT_READ: "project:read",
  EVENT_READ: "event:read",
  MONITOR_READ: "monitor:read",
  POLICY_READ: "policy:read",
  REPORT_READ: "report:read",
  ML_READ: "ml:read",
  VULN_READ: "vuln:read",
  EXCEPTION_REQUEST: "exception:request",
  EXCEPTION_APPROVE: "exception:approve",
  EVENT_ACK: "event:ack",
  MONITOR_WRITE: "monitor:write",
  POLICY_WRITE: "policy:write",
  USER_MANAGE: "user:manage",
  SYSTEM_WRITE: "system:write",
  AUDIT_READ: "audit:read",
  SYSTEM_READ: "system:read",
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

const P = PERMISSIONS;
const ENGINEERING_WRITE: Permission[] = [P.SCAN_CREATE, P.PROJECT_WRITE, P.CONTAINER_SCAN, P.DIFF_CREATE];
const READ: Permission[] = [
  P.SCAN_READ,
  P.PROJECT_READ,
  P.EVENT_READ,
  P.MONITOR_READ,
  P.POLICY_READ,
  P.REPORT_READ,
  P.ML_READ,
  P.VULN_READ,
];
const SECOPS: Permission[] = [P.EXCEPTION_APPROVE, P.EVENT_ACK, P.MONITOR_WRITE];
const OVERSIGHT: Permission[] = [P.AUDIT_READ, P.SYSTEM_READ];

export const ROLE_PERMISSIONS: Readonly<Record<UserRole, ReadonlySet<Permission>>> = {
  admin: new Set(Object.values(PERMISSIONS)),
  security_analyst: new Set([...ENGINEERING_WRITE, ...READ, P.EXCEPTION_REQUEST, ...SECOPS]),
  developer: new Set([...ENGINEERING_WRITE, ...READ, P.EXCEPTION_REQUEST]),
  auditor: new Set([...READ, ...OVERSIGHT]),
  read_only: new Set(READ),
};

/** v1 role names accepted by the server and mapped to Warden roles. */
export const LEGACY_ROLE_NAMES: Readonly<Record<string, UserRole>> = {
  analyst: "security_analyst",
  viewer: "read_only",
};

export const ROLE_LABELS: Readonly<Record<UserRole, string>> = {
  admin: "Admin",
  security_analyst: "Security analyst",
  developer: "Developer",
  auditor: "Auditor",
  read_only: "Read only",
};

const EMPTY: ReadonlySet<Permission> = new Set();

/** Canonical current role for `role` (legacy names accepted), or null when unknown. */
export function normalizeRole(role: string | null | undefined): UserRole | null {
  if (typeof role !== "string") return null;
  const key = role.trim().toLowerCase();
  const mapped = Object.prototype.hasOwnProperty.call(LEGACY_ROLE_NAMES, key) ? LEGACY_ROLE_NAMES[key] : key;
  return (USER_ROLES as readonly string[]).includes(mapped ?? "") ? (mapped as UserRole) : null;
}

export function permissionsFor(role: string | null | undefined): ReadonlySet<Permission> {
  const resolved = normalizeRole(role);
  return resolved ? ROLE_PERMISSIONS[resolved] : EMPTY;
}

/** True when `role` holds every permission listed. An empty list is never "allowed". */
export function hasPermission(role: string | null | undefined, ...perms: Permission[]): boolean {
  if (perms.length === 0) return false;
  const granted = permissionsFor(role);
  return perms.every((p) => granted.has(p));
}
