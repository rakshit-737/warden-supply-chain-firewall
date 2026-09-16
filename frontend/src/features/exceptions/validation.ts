import { ENVIRONMENTS, FINDING_CATEGORIES, type Environment, type PolicyExceptionCreate } from "../../api/types";
import { NON_OVERRIDABLE_CODES } from "./taxonomy";

/*
 * Client-side mirror of the server's exception rules (backend app/schemas/exception.py `ExceptionCreate`
 * and `ExceptionTransition`, app/schemas/scan.py `PYPI_NAME_RE`). These checks only report mistakes
 * before a request is sent; the server validates every request again and its answer wins.
 */

export const MAX_EXCEPTION_DAYS = 365;
export const MIN_JUSTIFICATION_CHARS = 10;
export const MAX_JUSTIFICATION_CHARS = 2000;
export const MAX_COMMENT_CHARS = 500;
export const MAX_PACKAGE_NAME_CHARS = 214;
export const MAX_VERSION_SPEC_CHARS = 100;
export const MAX_CODES = 50;
export const MAX_CATEGORIES = 25;

const DAY_MS = 86_400_000;

/** PEP 508 project name, capped at 214 characters (backend `PYPI_NAME_RE`). */
export const PACKAGE_NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,212}[A-Za-z0-9])?$/;

/** Length in code points, as Python counts it (a string's `length` counts UTF-16 units). */
export function charCount(text: string): number {
  return [...text].length;
}

/** PEP 503 normalisation, as the server stores the name: runs of "-", "_" and "." become "-", lower case. */
export function normalizePackageName(name: string): string {
  return name.trim().replace(/[-_.]+/g, "-").toLowerCase();
}

export function isValidPackageName(name: string): boolean {
  return PACKAGE_NAME_RE.test(name.trim());
}

export function packageNameError(raw: string): string | null {
  if (charCount(raw) > MAX_PACKAGE_NAME_CHARS) return `Package names can be at most ${MAX_PACKAGE_NAME_CHARS} characters.`;
  const name = raw.trim();
  if (!name) return "Enter the package name.";
  if (!PACKAGE_NAME_RE.test(name)) {
    return "Enter a valid PyPI package name: letters, digits, dots, hyphens and underscores, starting and ending with a letter or digit.";
  }
  return null;
}

// PEP 440 specifier clauses, following packaging.specifiers.Specifier (the parser the server uses).
const EPOCH = "(?:[0-9]+!)?";
const RELEASE = "[0-9]+(?:\\.[0-9]+)*";
const PRE = "(?:[-_.]?(?:alpha|beta|preview|pre|a|b|c|rc)[-_.]?[0-9]*)?";
const POST = "(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?";
const DEV = "(?:[-_.]?dev[-_.]?[0-9]*)?";
const LOCAL = "(?:\\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?";
const CLAUSE_PATTERNS: readonly RegExp[] = [
  // Arbitrary equality: an exact string match of anything without whitespace, ";" or ")".
  /^===\s*[^\s;)]*$/i,
  // (Non-)equality allows a trailing ".*" wildcard or a local version.
  new RegExp(`^(?:==|!=)\\s*v?${EPOCH}${RELEASE}(?:\\.\\*|${PRE}${POST}${DEV}${LOCAL})$`, "i"),
  // Compatible release needs at least two release segments.
  new RegExp(`^~=\\s*v?${EPOCH}[0-9]+(?:\\.[0-9]+)+${PRE}${POST}${DEV}$`, "i"),
  // Ordered comparisons allow neither wildcards nor local versions.
  new RegExp(`^(?:<=|>=|<|>)\\s*v?${EPOCH}${RELEASE}${PRE}${POST}${DEV}$`, "i"),
];

export type Checked<T> = { ok: true; value: T } | { ok: false; error: string };

/**
 * A PEP 440 specifier set such as ">=1.4,<2.0". Empty input means every version (null). The value
 * returned has the whitespace removed; the server additionally sorts the clauses.
 */
export function checkVersionSpec(raw: string): Checked<string | null> {
  if (charCount(raw) > MAX_VERSION_SPEC_CHARS) {
    return { ok: false, error: `Version specifiers can be at most ${MAX_VERSION_SPEC_CHARS} characters.` };
  }
  if (!raw.trim()) return { ok: true, value: null };
  const clauses = raw
    .split(",")
    .map((clause) => clause.trim())
    .filter(Boolean);
  if (clauses.length === 0) return { ok: false, error: "Enter at least one version clause, such as <2.0." };
  if (!clauses.every((clause) => CLAUSE_PATTERNS.some((pattern) => pattern.test(clause)))) {
    return {
      ok: false,
      error: "Use PEP 440 specifiers separated by commas, such as >=1.4,<2.0 or ==1.4.*. Each clause needs an operator.",
    };
  }
  const normalised = clauses.map((clause) => clause.replace(/\s+/g, "")).join(",");
  if (charCount(normalised) > MAX_VERSION_SPEC_CHARS) {
    return { ok: false, error: `Version specifiers can be at most ${MAX_VERSION_SPEC_CHARS} characters.` };
  }
  return { ok: true, value: normalised };
}

export function justificationError(raw: string): string | null {
  if (charCount(raw) > MAX_JUSTIFICATION_CHARS) {
    return `The justification can be at most ${MAX_JUSTIFICATION_CHARS} characters.`;
  }
  const length = charCount(raw.trim());
  if (length === 0) return "Explain why this exception is needed.";
  if (length < MIN_JUSTIFICATION_CHARS) return `Write at least ${MIN_JUSTIFICATION_CHARS} characters of justification.`;
  return null;
}

/** Approve, reject and revoke comments. The server accepts an empty comment; this console requires one. */
export function commentError(raw: string): string | null {
  if (!raw.trim()) return "Enter a comment. It is recorded in the audit trail with this action.";
  if (charCount(raw) > MAX_COMMENT_CHARS) return `Comments can be at most ${MAX_COMMENT_CHARS} characters.`;
  return null;
}

export function codesError(codes: readonly string[]): string | null {
  if (codes.length > MAX_CODES) return `Select at most ${MAX_CODES} finding codes.`;
  const blocked = codes.find((code) => NON_OVERRIDABLE_CODES.includes(code.trim().toUpperCase()));
  if (blocked) return `${blocked} findings are non-overridable and cannot be excepted.`;
  if (!codes.every((code) => /^[A-Z][A-Z0-9_]{1,63}$/.test(code.trim().toUpperCase()))) {
    return "Finding codes look like NETWORK_EGRESS.";
  }
  return null;
}

export function categoriesError(categories: readonly string[]): string | null {
  if (categories.length > MAX_CATEGORIES) return `Select at most ${MAX_CATEGORIES} finding categories.`;
  const known: readonly string[] = FINDING_CATEGORIES;
  if (!categories.every((category) => known.includes(category.trim().toLowerCase()))) {
    return "Select categories from the list.";
  }
  return null;
}

function pad(value: number, width = 2): string {
  return String(value).padStart(width, "0");
}

/** YYYY-MM-DD of `date` in the local time zone (the value format of an `<input type="date">`). */
export function localDateString(date: Date): string {
  return `${pad(date.getFullYear(), 4)}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** Local midnight at the start of a YYYY-MM-DD date, or null when it is not a real calendar date. */
export function parseLocalDate(value: string): Date | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value.trim());
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(year, month - 1, day);
  if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) return null;
  return date;
}

/**
 * Selectable expiry dates. An exception stops applying at local midnight at the start of the chosen date,
 * which must be after `now` and at most 365 days after it.
 */
export function expiryBounds(now: number): { min: string; max: string } {
  const today = new Date(now);
  const tomorrow = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);
  return { min: localDateString(tomorrow), max: localDateString(new Date(now + MAX_EXCEPTION_DAYS * DAY_MS)) };
}

export function checkExpiry(value: string, now: number): Checked<Date> {
  if (!value.trim()) return { ok: false, error: "Choose the date the exception expires." };
  const date = parseLocalDate(value);
  if (!date) return { ok: false, error: "Enter the expiry as a calendar date." };
  if (date.getTime() <= now) return { ok: false, error: "The expiry date must be after today." };
  if (date.getTime() > now + MAX_EXCEPTION_DAYS * DAY_MS) {
    return { ok: false, error: `The expiry date can be at most ${MAX_EXCEPTION_DAYS} days from now.` };
  }
  return { ok: true, value: date };
}

export interface ExceptionFormValues {
  package: string;
  versionSpec: string;
  codes: string[];
  categories: string[];
  /** "" = every policy. */
  policyId: string;
  /** "" = every environment. */
  environment: Environment | "";
  justification: string;
  /** YYYY-MM-DD. */
  expiresOn: string;
}

export type ExceptionFormField = keyof ExceptionFormValues;
export type ExceptionFormErrors = Partial<Record<ExceptionFormField, string>>;

export const EMPTY_EXCEPTION_FORM: ExceptionFormValues = {
  package: "",
  versionSpec: "",
  codes: [],
  categories: [],
  policyId: "",
  environment: "",
  justification: "",
  expiresOn: "",
};

/** Field order used for error summaries and for choosing which field receives focus. */
export const EXCEPTION_FORM_FIELDS: readonly ExceptionFormField[] = [
  "package",
  "versionSpec",
  "policyId",
  "environment",
  "categories",
  "codes",
  "justification",
  "expiresOn",
];

/**
 * Validate the request form. `policyEnvironment` is the environment of the selected policy, if any: the
 * server refuses a request whose environment differs from it.
 */
export function validateExceptionForm(
  values: ExceptionFormValues,
  now: number,
  policyEnvironment: string | null = null,
): { errors: ExceptionFormErrors; body: PolicyExceptionCreate | null } {
  const errors: ExceptionFormErrors = {};
  const packageError = packageNameError(values.package);
  if (packageError) errors.package = packageError;
  const spec = checkVersionSpec(values.versionSpec);
  if (!spec.ok) errors.versionSpec = spec.error;
  const environment = values.environment === "" ? null : values.environment;
  if (environment !== null && !(ENVIRONMENTS as readonly string[]).includes(environment)) {
    errors.environment = "Choose an environment from the list.";
  } else if (values.policyId && policyEnvironment && environment !== null && environment !== policyEnvironment) {
    errors.environment = "The environment must match the selected policy's environment.";
  }
  const categoryError = categoriesError(values.categories);
  if (categoryError) errors.categories = categoryError;
  const codeError = codesError(values.codes);
  if (codeError) errors.codes = codeError;
  const reasonError = justificationError(values.justification);
  if (reasonError) errors.justification = reasonError;
  const expiry = checkExpiry(values.expiresOn, now);
  if (!expiry.ok) errors.expiresOn = expiry.error;

  if (Object.keys(errors).length > 0 || !spec.ok || !expiry.ok) return { errors, body: null };
  const body: PolicyExceptionCreate = {
    package: values.package.trim(),
    codes: [...values.codes],
    categories: [...values.categories],
    justification: values.justification.trim(),
    expires_at: expiry.value.toISOString(),
  };
  if (spec.value !== null) body.version_spec = spec.value;
  if (values.policyId) body.policy_id = values.policyId;
  if (environment !== null) body.environment = environment;
  return { errors, body };
}
