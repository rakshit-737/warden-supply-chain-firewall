import axios, { AxiosError, AxiosInstance } from "axios";

/**
 * API client with in-memory access-token storage and transparent refresh.
 *
 * The access token is intentionally kept only in memory (never localStorage) to reduce
 * XSS token-theft impact; the long-lived refresh token lives in an httpOnly cookie the JS
 * cannot read. On a 401 the client transparently attempts a single refresh and retries.
 */

let accessToken: string | null = null;
let onLogout: (() => void) | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}
export function registerLogoutHandler(fn: () => void) {
  onLogout = fn;
}

export const api: AxiosInstance = axios.create({
  baseURL: "/api/v1",
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

let refreshing: Promise<string | null> | null = null;

async function refreshToken(): Promise<string | null> {
  try {
    const resp = await axios.post(
      "/api/v1/auth/refresh",
      {},
      { withCredentials: true },
    );
    const token = resp.data.access_token as string;
    setAccessToken(token);
    return token;
  } catch {
    return null;
  }
}

api.interceptors.response.use(
  (r) => r,
  async (error: AxiosError) => {
    const original = error.config as typeof error.config & { _retried?: boolean };
    const status = error.response?.status;
    const isAuthCall = original?.url?.includes("/auth/");
    if (status === 401 && original && !original._retried && !isAuthCall) {
      original._retried = true;
      refreshing = refreshing || refreshToken();
      const token = await refreshing;
      refreshing = null;
      if (token) {
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);
      }
      onLogout?.();
    }
    return Promise.reject(error);
  },
);

export function apiErrorMessage(err: unknown): string {
  const e = err as AxiosError<{ error?: { message?: string } }>;
  return e.response?.data?.error?.message || e.message || "Unexpected error";
}
