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
      { to: "/graph", label: "Dependency graph", permission: P.PROJECT_READ },
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

export interface PlannedSection {
  path: string;
  title: string;
  summary: string;
  permission: Permission;
}

/** Sections that have a route and navigation entry but no view yet. */
export const PLANNED_SECTIONS: readonly PlannedSection[] = [
  {
    path: "packages",
    title: "Packages",
    summary: "Per-package history: versions scanned, risk over time and related security events.",
    permission: P.SCAN_READ,
  },
  {
    path: "projects",
    title: "Projects",
    summary: "Project scans built from dependency manifests, with SBOM export and policy results.",
    permission: P.PROJECT_READ,
  },
  {
    path: "graph",
    title: "Dependency graph",
    summary: "Transitive dependencies of a project scan, with blast radius and single points of failure.",
    permission: P.PROJECT_READ,
  },
  {
    path: "diffs",
    title: "Release diffs",
    summary: "Behavioural comparison between two releases of the same package.",
    permission: P.SCAN_READ,
  },
  {
    path: "containers",
    title: "Containers",
    summary: "Results of container image, Dockerfile and Compose scans.",
    permission: P.SCAN_READ,
  },
  {
    path: "monitoring",
    title: "Monitoring",
    summary: "Packages watched for new releases and changes in risk.",
    permission: P.MONITOR_READ,
  },
];
