import axios, { AxiosHeaders, type AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from "axios";
import type { ApiErrorBody, TokenResponse } from "./types";

/**
 * API client with in-memory access-token storage and transparent refresh.
 *
 * The access token is intentionally kept only in memory (never localStorage/sessionStorage)
 * to reduce the impact of XSS token theft; the long-lived refresh token lives in an httpOnly
 * cookie that JavaScript cannot read. On a 401 the client attempts a single refresh (shared by
 * concurrent requests) and retries the original request once. Only a refresh the server refuses
 * signs the user out. A refresh that is rate limited, fails on the server or cannot reach it fails
 * the original request instead and keeps the session for the next attempt.
 */

const API_BASE = "/api/v1";

/** How long a refresh may take before it counts as a transient failure. */
const REFRESH_TIMEOUT_MS = 30_000;

/** `ApiError.code` for a request this client stopped waiting for. The server may still process it. */
export const CLIENT_TIMEOUT_CODE = "client_timeout";

let accessToken: string | null = null;
let onLogout: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function registerLogoutHandler(fn: (() => void) | null): void {
  onLogout = fn;
}

export const api: AxiosInstance = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  timeout: 120_000,
  // Timeouts reject with ETIMEDOUT instead of ECONNABORTED, which axios also uses for requests the
  // browser aborted. The defaults are spread in because this option replaces the whole object.
  transitional: { ...axios.defaults.transitional, clarifyTimeoutError: true },
});

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.set("Authorization", `Bearer ${accessToken}`);
  }
  return config;
});

/**
 * True when the server definitively refused the session: the refresh cookie or access token is
 * missing, invalid, expired or revoked. Rate limiting (429), request timeouts (408), server errors,
 * client-side timeouts and network failures say nothing about the session, so they are not refusals.
 */
export function isSessionRejection(err: unknown): boolean {
  if (!axios.isAxiosError(err)) return false;
  const status = err.response?.status;
  return status !== undefined && status >= 400 && status < 500 && status !== 408 && status !== 429;
}

let refreshing: Promise<string | null> | null = null;

async function requestAccessToken(): Promise<string | null> {
  try {
    const resp = await axios.post<TokenResponse>(
      `${API_BASE}/auth/refresh`,
      {},
      { withCredentials: true, timeout: REFRESH_TIMEOUT_MS },
    );
    const token = typeof resp.data.access_token === "string" ? resp.data.access_token : null;
    setAccessToken(token);
    return token;
  } catch (err) {
    if (!isSessionRejection(err)) throw err;
    setAccessToken(null);
    return null;
  }
}

/**
 * Exchange the httpOnly refresh cookie for a new access token. Resolves to null when the server
 * refuses the session, and rejects when the server could not answer (see isSessionRejection).
 * Concurrent callers share one request: the server rotates the refresh token on every use and
 * treats a replayed token as theft, revoking the whole session, so parallel refreshes (several 401s
 * at once, React StrictMode running effects twice) must never be sent.
 */
export function refreshSession(): Promise<string | null> {
  refreshing ??= requestAccessToken().finally(() => {
    refreshing = null;
  });
  return refreshing;
}

type RetriableConfig = InternalAxiosRequestConfig & { _retried?: boolean };

api.interceptors.response.use(
  (r) => r,
  async (error: AxiosError) => {
    const original = error.config as RetriableConfig | undefined;
    const status = error.response?.status;
    const isAuthCall = original?.url?.startsWith("/auth/") ?? false;
    if (status === 401 && original && !original._retried && !isAuthCall) {
      original._retried = true;
      // A transient refresh failure rejects here: the original request then fails with that error
      // (for example 429 with its Retry-After) and the user stays signed in.
      const token = await refreshSession();
      if (token) {
        original.headers.set("Authorization", `Bearer ${token}`);
        return api(original);
      }
      onLogout?.();
    }
    return Promise.reject(error);
  },
);

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

export interface ApiError {
  /** HTTP status, or null for network failures and client-side errors. */
  status: number | null;
  /** Server error code from `{"error": {"code"}}`, CLIENT_TIMEOUT_CODE, or null. */
  code: string | null;
  message: string;
  /** Server request id, for correlating with backend logs. */
  requestId: string | null;
  /** Seconds the server asked the client to wait before retrying (Retry-After), when it said so. */
  retryAfterSeconds?: number | null;
}

function isErrorBody(data: unknown): data is ApiErrorBody {
  if (typeof data !== "object" || data === null || !("error" in data)) return false;
  const inner = data.error;
  return typeof inner === "object" && inner !== null;
}

const STATUS_MESSAGES: Record<number, string> = {
  401: "Your session has ended. Sign in again.",
  403: "Your role does not allow this action.",
  404: "Not found. It may have been removed, or this server does not provide it yet.",
  429: "Too many requests. Wait a moment and try again.",
  502: "The Warden API could not be reached through the web server. Try again shortly.",
  503: "The Warden API is temporarily unavailable. Try again shortly.",
  504: "The Warden API did not answer in time. The request may still be processed.",
};

const MAX_RETRY_AFTER_SECONDS = 3600;

function headerValue(headers: unknown, name: string): unknown {
  if (headers instanceof AxiosHeaders) return headers.get(name);
  if (typeof headers !== "object" || headers === null) return undefined;
  const wanted = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === wanted)?.[1];
}

/** Retry-After as whole seconds (delta-seconds or an HTTP date), capped at one hour. */
function parseRetryAfter(value: unknown): number | null {
  if (typeof value !== "string" || value.trim() === "") return null;
  const text = value.trim();
  let seconds: number;
  if (/^\d+$/.test(text)) {
    seconds = Number(text);
  } else {
    const date = Date.parse(text);
    if (Number.isNaN(date)) return null;
    seconds = Math.ceil((date - Date.now()) / 1000);
  }
  return Number.isFinite(seconds) ? Math.min(Math.max(seconds, 0), MAX_RETRY_AFTER_SECONDS) : null;
}

export function toApiError(err: unknown): ApiError {
  if (axios.isAxiosError(err)) {
    const status = err.response?.status ?? null;
    const retryAfterSeconds = parseRetryAfter(headerValue(err.response?.headers, "retry-after"));
    const data: unknown = err.response?.data;
    if (isErrorBody(data)) {
      const { code, message, request_id } = data.error;
      return {
        status,
        code: typeof code === "string" ? code : null,
        message:
          typeof message === "string" && message
            ? message
            : ((status !== null && STATUS_MESSAGES[status]) || "The request failed."),
        requestId: typeof request_id === "string" ? request_id : null,
        retryAfterSeconds,
      };
    }
    if (status !== null) {
      return {
        status,
        code: null,
        message: STATUS_MESSAGES[status] ?? `The server responded with HTTP ${status}.`,
        requestId: null,
        retryAfterSeconds,
      };
    }
    if (err.code === "ETIMEDOUT") {
      return {
        status: null,
        code: CLIENT_TIMEOUT_CODE,
        message: "The Warden API did not answer in time. The request may still be processed.",
        requestId: null,
        retryAfterSeconds: null,
      };
    }
    return {
      status: null,
      code: null,
      message: "Could not reach the Warden API. Check your connection.",
      requestId: null,
      retryAfterSeconds: null,
    };
  }
  if (err instanceof Error) return { status: null, code: null, message: err.message, requestId: null };
  return { status: null, code: null, message: "Unexpected error.", requestId: null };
}

/** v1-compatible helper: a human-readable message for any thrown value. */
export function apiErrorMessage(err: unknown): string {
  return toApiError(err).message;
}

/** True for requests cancelled through an AbortSignal (not a real failure). */
export function isAbortError(err: unknown): boolean {
  return axios.isCancel(err) || (err instanceof Error && (err.name === "AbortError" || err.name === "CanceledError"));
}

// ---------------------------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------------------------

export interface RequestOptions {
  signal?: AbortSignal;
}

/**
 * Encode one URL path segment. Ids and package names are interpolated into API paths, so a
 * value such as "../users" must never be able to address a different endpoint: the value is
 * percent-encoded (so "/" and "?" cannot survive) and dot segments are rejected outright
 * because browsers normalise "." and ".." even when they stand alone.
 */
export function pathSegment(value: string | number): string {
  const s = String(value);
  if (s.length === 0 || s === "." || s === "..") {
    throw new Error("Invalid identifier in request path.");
  }
  return encodeURIComponent(s);
}

/** Drop undefined/null/empty-string params so they are not sent as literal "undefined". */
export function cleanParams<T extends object>(params: T | undefined): Partial<T> | undefined {
  if (!params) return undefined;
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(params) as [keyof T, T[keyof T]][]) {
    if (v !== undefined && v !== null && v !== "") out[k] = v;
  }
  return out;
}
