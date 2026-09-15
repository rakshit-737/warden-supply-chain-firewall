import type { Location } from "../api/types";

/**
 * DOM id for a finding's card. Shared by FindingCard and by links from attack chains and policy
 * reasons. Finding ids come from the server; anything outside [A-Za-z0-9_-] is replaced so the
 * id is always a plain token.
 */
export function findingAnchorId(findingId: string): string {
  return `finding-${findingId.replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 80)}`;
}

/**
 * "path/in/package.py:12" when the file is known, the bare file when the line is not. A line is
 * only shown when the analyzer reported a positive integer; a position is never invented.
 */
export function formatLocation(location: Location | null | undefined): string | null {
  if (!location || typeof location.file !== "string" || location.file.trim() === "") return null;
  const { line } = location;
  return typeof line === "number" && Number.isInteger(line) && line > 0 ? `${location.file}:${line}` : location.file;
}
