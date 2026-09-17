import { PERMISSIONS, type Permission } from "../auth/permissions";

export interface NavItem {
  to: string;
  label: string;
  end?: boolean;
  /** Hide the item when the role lacks this permission (UI only; the server enforces access). */
  permission?: Permission;
}

export interface NavSection {
  id: string;
  label: string;
  items: NavItem[];
}

const P = PERMISSIONS;

export const NAV_SECTIONS: readonly NavSection[] = [
  { id: "overview", label: "Overview", items: [{ to: "/", label: "Dashboard", end: true }] },
  {
    id: "supply-chain",
    label: "Supply chain",
    items: [
      { to: "/scans", label: "Scans", permission: P.SCAN_READ },
      { to: "/packages", label: "Packages", permission: P.SCAN_READ },
      { to: "/projects", label: "Projects", permission: P.PROJECT_READ },
      { to: "/diffs", label: "Release diffs", permission: P.SCAN_READ },
      { to: "/containers", label: "Containers", permission: P.SCAN_READ },
    ],
  },
  {
    id: "operations",
    label: "Operations",
    items: [
      { to: "/events", label: "Events", permission: P.EVENT_READ },
      { to: "/monitoring", label: "Monitoring", permission: P.MONITOR_READ },
    ],
  },
  {
    id: "governance",
    label: "Governance",
    items: [
      { to: "/policies", label: "Policies", permission: P.POLICY_READ },
      { to: "/exceptions", label: "Exceptions", permission: P.POLICY_READ },
      { to: "/audit", label: "Audit", permission: P.AUDIT_READ },
    ],
  },
  {
    id: "administration",
    label: "Administration",
    items: [
      { to: "/users", label: "Users", permission: P.USER_MANAGE },
      { to: "/system", label: "System", permission: P.SYSTEM_READ },
    ],
  },
];
