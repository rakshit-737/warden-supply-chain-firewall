import { EVENT_TYPES, SEVERITIES, type EventType, type ListEventsParams, type Severity } from "../../api/types";
import { pickOption } from "../../lib/values";
import { isUuid, parseOffset } from "./searchParams";
import { fromLocalInputValue } from "./time";

/** Query-string names; they match the API parameter names. */
export const EVENT_FILTER_PARAMS = ["type", "severity", "package", "project_id", "since", "acknowledged"] as const;
export type EventFilterParam = (typeof EVENT_FILTER_PARAMS)[number] | "offset";

export const EVENT_FILTER_LABEL: Record<EventFilterParam, string> = {
  type: "type",
  severity: "severity",
  package: "package",
  project_id: "project ID",
  since: "since",
  acknowledged: "status",
  offset: "page",
};

/** Server bounds (backend routers/events.py). */
export const MAX_PACKAGE_LENGTH = 214;
export const MAX_EVENT_OFFSET = 1_000_000;

export interface EventFilters {
  type?: EventType;
  severity?: Severity;
  package?: string;
  projectId?: string;
  /** ISO 8601 UTC timestamp. */
  since?: string;
  acknowledged?: boolean;
}

export interface EventQueryState {
  filters: EventFilters;
  offset: number;
  /** Parameters present in the address but not valid, so not sent to the server. */
  ignored: EventFilterParam[];
}

// Date or date-time as produced by toISOString() or typed by hand; Date.parse decides validity.
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/i;

export function parseSinceParam(value: string): string | null {
  const text = value.trim();
  if (!ISO_TIMESTAMP_RE.test(text)) return null;
  const time = Date.parse(text);
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

/** Reads event filters from the address. Invalid values are dropped and reported, never sent. */
export function readEventQuery(params: URLSearchParams): EventQueryState {
  const ignored: EventFilterParam[] = [];
  const present = (name: EventFilterParam): string | null => {
    const raw = params.get(name);
    return raw === null || raw.trim() === "" ? null : raw.trim();
  };
  const filters: EventFilters = {};

  const type = present("type");
  if (type !== null) {
    filters.type = pickOption(EVENT_TYPES, type.toLowerCase());
    if (!filters.type) ignored.push("type");
  }
  const severity = present("severity");
  if (severity !== null) {
    filters.severity = pickOption(SEVERITIES, severity.toLowerCase());
    if (!filters.severity) ignored.push("severity");
  }
  const pkg = present("package");
  if (pkg !== null) {
    if (pkg.length <= MAX_PACKAGE_LENGTH) filters.package = pkg;
    else ignored.push("package");
  }
  const project = present("project_id");
  if (project !== null) {
    if (isUuid(project)) filters.projectId = project.toLowerCase();
    else ignored.push("project_id");
  }
  const since = present("since");
  if (since !== null) {
    const parsed = parseSinceParam(since);
    if (parsed) filters.since = parsed;
    else ignored.push("since");
  }
  const acknowledged = present("acknowledged");
  if (acknowledged !== null) {
    if (acknowledged === "true" || acknowledged === "false") filters.acknowledged = acknowledged === "true";
    else ignored.push("acknowledged");
  }
  let offset = parseOffset(params.get("offset"), MAX_EVENT_OFFSET);
  if (offset === null) {
    ignored.push("offset");
    offset = 0;
  }
  return { filters, offset, ignored };
}

export function hasActiveEventFilters(filters: EventFilters): boolean {
  return Object.values(filters).some((value) => value !== undefined);
}

export function toListEventsParams(filters: EventFilters, offset: number, limit: number): ListEventsParams {
  return {
    limit,
    offset,
    type: filters.type,
    severity: filters.severity,
    package: filters.package,
    project_id: filters.projectId,
    since: filters.since,
    acknowledged: filters.acknowledged,
  };
}

/** The free-text filters, applied together on submit. `since` is a datetime-local value. */
export interface EventTextDraft {
  package: string;
  projectId: string;
  since: string;
}

export type EventTextErrors = Partial<Record<keyof EventTextDraft, string>>;

export interface EventTextValues {
  package: string | null;
  projectId: string | null;
  since: string | null;
}

/** Tolerance for a "since" time slightly ahead of this device's clock. */
const FUTURE_TOLERANCE_MS = 60_000;

export interface EventTextValidationOptions {
  /** Epoch milliseconds to compare "since" against; defaults to the current time. */
  now?: number;
  /** The browser reports the datetime-local input as only partly filled in (validity.badInput). */
  sinceIncomplete?: boolean;
}

/** Validates the text filters. Called from event handlers, so it may read the clock. */
export function validateEventTextFilters(
  draft: EventTextDraft,
  { now = Date.now(), sinceIncomplete = false }: EventTextValidationOptions = {},
): { errors: EventTextErrors; values: EventTextValues } {
  const errors: EventTextErrors = {};
  const pkg = draft.package.trim();
  if (pkg.length > MAX_PACKAGE_LENGTH) {
    errors.package = `Package names can be at most ${MAX_PACKAGE_LENGTH} characters.`;
  }
  const project = draft.projectId.trim();
  if (project !== "" && !isUuid(project)) {
    errors.projectId = "Enter the project ID as a UUID, for example 3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b.";
  }
  let since: string | null = null;
  if (sinceIncomplete) {
    errors.since = "Enter a complete date and time, or clear the field.";
  } else if (draft.since.trim() !== "") {
    since = fromLocalInputValue(draft.since);
    if (since === null) errors.since = "Enter a valid date and time, or clear the field.";
    else if (Date.parse(since) > now + FUTURE_TOLERANCE_MS) errors.since = "Choose a time that is not in the future.";
  }
  return {
    errors,
    values: { package: pkg || null, projectId: project ? project.toLowerCase() : null, since },
  };
}

export const SINCE_PRESETS = [
  { id: "1h", label: "1 hour", description: "Since 1 hour ago", ms: 3_600_000 },
  { id: "24h", label: "24 hours", description: "Since 24 hours ago", ms: 86_400_000 },
  { id: "7d", label: "7 days", description: "Since 7 days ago", ms: 7 * 86_400_000 },
  { id: "30d", label: "30 days", description: "Since 30 days ago", ms: 30 * 86_400_000 },
] as const;

/** `ms` before `now` (default: the current time), rounded down to the minute so the address stays readable. */
export function sinceBefore(ms: number, now = Date.now()): string {
  return new Date(Math.floor((now - ms) / 60_000) * 60_000).toISOString();
}
