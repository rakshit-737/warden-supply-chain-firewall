import type { EventType } from "../../api/types";
import { humanize } from "../../lib/format";

export const EVENT_TYPE_LABEL: Record<EventType, string> = {
  package_scanned: "Package scanned",
  package_blocked: "Package blocked",
  risk_increased: "Risk increased",
  risk_decreased: "Risk decreased",
  vulnerability_discovered: "Vulnerability discovered",
  kev_added: "Known exploited vulnerability added",
  behavior_drift_detected: "Behaviour drift detected",
  maintainer_changed: "Maintainer changed",
  provenance_changed: "Provenance changed",
  new_release_detected: "New release detected",
  policy_violation: "Policy violation",
  exception_created: "Policy exception requested",
  exception_approved: "Policy exception approved",
  exception_rejected: "Policy exception rejected",
  exception_revoked: "Policy exception revoked",
  exception_expired: "Policy exception expired",
  sbom_generated: "SBOM generated",
  project_scanned: "Project scanned",
  container_scanned: "Container scanned",
  dependency_graph_changed: "Dependency graph changed",
  monitor_error: "Monitoring error",
};

/** Label for a known event type; a readable form of the raw value for types this console does not know. */
export function eventTypeLabel(type: string): string {
  return Object.prototype.hasOwnProperty.call(EVENT_TYPE_LABEL, type) ? EVENT_TYPE_LABEL[type as EventType] : humanize(type);
}

/** Scan detail page. */
export function scanPath(scanId: string): string {
  return `/scans/${encodeURIComponent(scanId)}`;
}

/** Scan list filtered to a package name (there is no package page yet). */
export function packageScansPath(pkg: string): string {
  return `/scans?${new URLSearchParams({ q: pkg }).toString()}`;
}
