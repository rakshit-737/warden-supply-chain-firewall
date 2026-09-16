import { humanize } from "../../lib/format";
import { revealInvisible, toDisplayText } from "../../lib/text";
import { isRecord, textOrNull } from "../../lib/values";

/**
 * Presentation of GET /system/info and GET /system/tools.
 *
 * api/types.ts describes the current backend exactly, but a server of another version can add, drop
 * or reshape keys. Everything here therefore reads the payload as unknown: a missing value reads
 * "Not reported", a value of an unexpected type is shown as text, and keys a newer server adds are
 * still listed (see unlistedSettings) rather than silently dropped.
 */

export type SettingFormat =
  | "switch"
  | "yesNo"
  | "bytes"
  | "seconds"
  | "perMinute"
  | "count"
  | "text"
  | "version"
  | "environment"
  | "cacheBackend"
  | "auto";

export interface SettingSpec {
  path: readonly string[];
  label: string;
  format: SettingFormat;
}

export interface SettingGroupSpec {
  id: string;
  title: string;
  note?: string;
  settings: readonly SettingSpec[];
}

export interface SettingRow {
  key: string;
  label: string;
  format: SettingFormat;
  value: unknown;
}

export interface SettingGroup {
  id: string;
  title: string;
  note?: string;
  rows: SettingRow[];
}

export const DEPLOYMENT_GROUP: SettingGroupSpec = {
  id: "deployment",
  title: "Deployment",
  settings: [
    { path: ["name"], label: "Product", format: "text" },
    { path: ["version"], label: "Server version", format: "version" },
    { path: ["env"], label: "Environment", format: "environment" },
    { path: ["analyzer_version"], label: "Analyzer version", format: "version" },
  ],
};

export const RUNTIME_GROUP: SettingGroupSpec = {
  id: "runtime",
  title: "Runtime",
  settings: [
    { path: ["runtime", "cache_backend"], label: "Cache and rate-limit backend", format: "cacheBackend" },
    { path: ["runtime", "trusted_proxies_configured"], label: "Trusted proxies configured", format: "yesNo" },
  ],
};

export const FEATURE_GROUPS: readonly SettingGroupSpec[] = [
  {
    id: "features-analysis",
    title: "Package analysis",
    settings: [
      { path: ["features", "provenance"], label: "Provenance checks", format: "switch" },
      { path: ["features", "analyze_wheels"], label: "Wheel analysis", format: "switch" },
      { path: ["features", "sandbox"], label: "Dynamic sandbox", format: "switch" },
      { path: ["features", "sbom_resolve_transitive"], label: "Resolve transitive dependencies in SBOMs", format: "switch" },
    ],
  },
  {
    id: "features-intel",
    title: "Vulnerability intelligence",
    settings: [
      { path: ["features", "intel", "enabled"], label: "Intelligence lookups", format: "switch" },
      { path: ["features", "intel", "offline"], label: "Offline mode", format: "switch" },
      { path: ["features", "intel", "nvd_enabled"], label: "NVD source", format: "switch" },
    ],
  },
  {
    id: "features-tools",
    title: "External analysis tools",
    note: "Configuration switches. Whether each tool is installed is listed under Analysis tools.",
    settings: [
      { path: ["features", "external_tools_enabled", "yara"], label: "YARA", format: "switch" },
      { path: ["features", "external_tools_enabled", "semgrep"], label: "Semgrep", format: "switch" },
      { path: ["features", "external_tools_enabled", "gitleaks"], label: "Gitleaks", format: "switch" },
    ],
  },
  {
    id: "features-operations",
    title: "Operations",
    settings: [
      { path: ["features", "monitoring"], label: "Release monitoring", format: "switch" },
      { path: ["features", "metrics", "enabled"], label: "Metrics endpoint", format: "switch" },
      { path: ["features", "metrics", "token_required"], label: "Metrics token required", format: "yesNo" },
      { path: ["features", "tracing", "enabled"], label: "Tracing", format: "switch" },
      { path: ["features", "tracing", "active"], label: "Tracing active", format: "yesNo" },
    ],
  },
];

export const LIMIT_GROUPS: readonly SettingGroupSpec[] = [
  {
    id: "limits-requests",
    title: "Requests",
    settings: [
      { path: ["limits", "max_request_body_bytes"], label: "Request body", format: "bytes" },
      { path: ["limits", "rate_limit_per_minute"], label: "API rate limit", format: "perMinute" },
      { path: ["limits", "auth_rate_limit_per_minute"], label: "Credential endpoint rate limit", format: "perMinute" },
    ],
  },
  {
    id: "limits-packages",
    title: "Package download and extraction",
    settings: [
      { path: ["limits", "max_download_bytes"], label: "Download", format: "bytes" },
      { path: ["limits", "max_extracted_bytes"], label: "Extracted contents", format: "bytes" },
      { path: ["limits", "max_extracted_files"], label: "Extracted files", format: "count" },
      { path: ["limits", "max_analyzed_file_bytes"], label: "Analyzed file", format: "bytes" },
      { path: ["limits", "max_metadata_bytes"], label: "Package metadata", format: "bytes" },
    ],
  },
  {
    id: "limits-projects",
    title: "Projects and graphs",
    settings: [
      { path: ["limits", "max_manifest_bytes"], label: "Manifest", format: "bytes" },
      { path: ["limits", "max_project_components"], label: "Components per project scan", format: "count" },
      { path: ["limits", "max_graph_nodes"], label: "Graph nodes", format: "count" },
    ],
  },
  {
    id: "limits-time",
    title: "Time and concurrency",
    settings: [
      { path: ["limits", "scan_timeout_seconds"], label: "Scan timeout", format: "seconds" },
      { path: ["limits", "analyzer_timeout_seconds"], label: "Analyzer timeout", format: "seconds" },
      { path: ["limits", "tool_timeout_seconds"], label: "External tool timeout", format: "seconds" },
      { path: ["limits", "analyzer_workers"], label: "Analyzer workers", format: "count" },
    ],
  },
];

const KNOWN_PATHS = new Set(
  [DEPLOYMENT_GROUP, RUNTIME_GROUP, ...FEATURE_GROUPS, ...LIMIT_GROUPS].flatMap((group) =>
    group.settings.map((setting) => setting.path.join(".")),
  ),
);

/** The value at `path`, or undefined when any step is missing or not an object. */
export function readPath(root: unknown, path: readonly string[]): unknown {
  let current: unknown = root;
  for (const key of path) {
    if (!isRecord(current) || !Object.prototype.hasOwnProperty.call(current, key)) return undefined;
    current = current[key];
  }
  return current;
}

export function settingGroup(info: unknown, spec: SettingGroupSpec): SettingGroup {
  return {
    id: spec.id,
    title: spec.title,
    note: spec.note,
    rows: spec.settings.map((setting) => ({
      key: setting.path.join("."),
      label: setting.label,
      format: setting.format,
      value: readPath(info, setting.path),
    })),
  };
}

const MAX_DEPTH = 4;

function collectLeaves(value: unknown, path: string[], out: { path: string[]; value: unknown }[]): void {
  if (isRecord(value) && path.length < MAX_DEPTH) {
    for (const [key, child] of Object.entries(value)) collectLeaves(child, [...path, key], out);
    return;
  }
  if (path.length > 0) out.push({ path, value });
}

/** Values in the payload that no known setting describes, such as keys added by a newer server. */
export function unlistedSettings(info: unknown): SettingRow[] {
  const leaves: { path: string[]; value: unknown }[] = [];
  collectLeaves(info, [], leaves);
  return leaves
    .map((leaf) => ({ key: leaf.path.join("."), value: leaf.value }))
    .filter((leaf) => !KNOWN_PATHS.has(leaf.key))
    .map((leaf) => ({ key: leaf.key, label: leaf.key, format: "auto" as const, value: leaf.value }));
}

// ---------------------------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------------------------

export interface FormattedSetting {
  text: string;
  /** on/off drive the switch glyph; missing is shown muted. */
  tone: "on" | "off" | "missing" | "plain";
  mono: boolean;
}

const integerFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const decimalFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const BYTE_UNITS = ["bytes", "KiB", "MiB", "GiB", "TiB"] as const;

const MISSING: FormattedSetting = { text: "Not reported", tone: "missing", mono: false };

function plain(text: string, mono = false): FormattedSetting {
  return { text: revealInvisible(text), tone: "plain", mono };
}

/** A value of an unexpected type: shown as text instead of being hidden. */
function asReported(value: unknown): FormattedSetting {
  return plain(toDisplayText(value), true);
}

function nonNegative(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/** 4194304 -> "4 MiB"; 1536 -> "1.5 KiB"; 512 -> "512 bytes". */
export function formatBytes(bytes: number): string {
  let scaled = bytes;
  let unit = 0;
  while (scaled >= 1024 && unit < BYTE_UNITS.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${integerFormat.format(bytes)} ${bytes === 1 ? "byte" : "bytes"}`;
  return `${decimalFormat.format(scaled)} ${BYTE_UNITS[unit] ?? "bytes"}`;
}

/** 180 -> "3 minutes"; 90 -> "90 seconds". */
export function formatSeconds(seconds: number): string {
  if (seconds >= 120 && seconds % 60 === 0) return `${integerFormat.format(seconds / 60)} minutes`;
  return `${decimalFormat.format(seconds)} ${seconds === 1 ? "second" : "seconds"}`;
}

const CACHE_BACKENDS: Readonly<Record<string, string>> = {
  redis: "Redis, shared by all API processes",
  in_process: "In-process, separate for each API process",
};

export function formatSetting(format: SettingFormat, value: unknown): FormattedSetting {
  if (value === undefined || value === null || value === "") return MISSING;
  switch (format) {
    case "switch":
      return typeof value === "boolean" ? { text: value ? "On" : "Off", tone: value ? "on" : "off", mono: false } : asReported(value);
    case "yesNo":
      return typeof value === "boolean" ? plain(value ? "Yes" : "No") : asReported(value);
    case "bytes": {
      const n = nonNegative(value);
      return n === null ? asReported(value) : plain(formatBytes(n));
    }
    case "seconds": {
      const n = nonNegative(value);
      return n === null ? asReported(value) : plain(formatSeconds(n));
    }
    case "perMinute": {
      const n = nonNegative(value);
      return n === null ? asReported(value) : plain(`${integerFormat.format(n)} per minute`);
    }
    case "count": {
      const n = nonNegative(value);
      return n === null ? asReported(value) : plain(integerFormat.format(n));
    }
    case "environment": {
      const text = textOrNull(value);
      return text === null ? asReported(value) : plain(humanize(text));
    }
    case "cacheBackend": {
      const text = textOrNull(value);
      if (text === null) return asReported(value);
      return plain(Object.prototype.hasOwnProperty.call(CACHE_BACKENDS, text) ? (CACHE_BACKENDS[text] ?? text) : text);
    }
    case "version":
    case "text": {
      const text = textOrNull(value);
      return text === null ? asReported(value) : plain(text, format === "version");
    }
    case "auto":
      if (typeof value === "boolean") return plain(value ? "Yes" : "No");
      if (typeof value === "number" && Number.isFinite(value)) return plain(decimalFormat.format(value));
      if (typeof value === "string") return plain(value);
      return asReported(value);
  }
}

// ---------------------------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------------------------

export interface ToolRow {
  /** Unique row key (tool names are unique on the server, but a malformed response might repeat one). */
  key: string;
  name: string;
  available: boolean;
  version: string | null;
  detail: string | null;
}

/** GET /system/tools entries that carry a name; `available` is true only when the server said so. */
export function readToolStatuses(value: unknown): ToolRow[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isRecord).flatMap((item, index) => {
    const name = textOrNull(item.name);
    if (name === null) return [];
    return [
      {
        key: `${index}:${name}`,
        name,
        available: item.available === true,
        version: textOrNull(item.version),
        detail: textOrNull(item.detail),
      },
    ];
  });
}
