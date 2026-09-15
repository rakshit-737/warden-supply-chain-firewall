// Runtime guards for server data. Types describe the intended contract, but scans recorded by
// older analyzers (and fields the spec leaves open) can hold anything, so views read through these.

export function textOrNull(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

export function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function booleanOrNull(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/** Non-empty strings from an array; anything else yields []. */
export function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim() !== "") : [];
}

/** `value` when it is one of `allowed` (e.g. a query-string filter), otherwise undefined. */
export function pickOption<T extends string>(allowed: readonly T[], value: string | null | undefined): T | undefined {
  return typeof value === "string" && (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Array items that are plain objects, typed as T (the caller still guards individual fields). */
export function recordArray<T>(value: unknown): T[] | null {
  return Array.isArray(value) ? (value.filter(isRecord) as T[]) : null;
}
