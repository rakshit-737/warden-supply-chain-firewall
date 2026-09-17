import { USER_ROLES, type UserRole } from "../../api/types";
import { ROLE_LABELS, normalizeRole } from "../../auth/permissions";
import type { SelectOption } from "../../components/SelectField";

export interface RoleDisplay {
  /** Canonical current role, or null when the server sent a name this console does not know. */
  role: UserRole | null;
  label: string;
  /** The name exactly as the server sent it, when that is not the canonical name (a v1 name such as "analyst"). */
  reportedAs: string | null;
}

/** Display form of a role as the API returned it. v1 names are shown as their current role. */
export function describeRole(value: unknown): RoleDisplay {
  const text = typeof value === "string" ? value : "";
  const role = normalizeRole(text);
  if (role === null) {
    return { role: null, label: "Unrecognised role", reportedAs: text.trim() === "" ? null : text };
  }
  return { role, label: ROLE_LABELS[role], reportedAs: text === role ? null : text };
}

/** What each role may do, in one line (SPEC section 6; the server enforces the matrix). */
export const ROLE_SUMMARIES: Readonly<Record<UserRole, string>> = {
  admin: "Everything, including users, policies and system settings.",
  security_analyst: "Runs scans, approves exceptions, acknowledges events and manages monitoring.",
  developer: "Runs scans and project scans, and can request policy exceptions.",
  auditor: "Reads everything, including the audit trail and system information. Changes nothing.",
  read_only: "Reads scans, projects, events, policies and reports. Changes nothing.",
};

export const ROLE_OPTIONS: readonly SelectOption[] = USER_ROLES.map((role) => ({ value: role, label: ROLE_LABELS[role] }));
