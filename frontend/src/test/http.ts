import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from "axios";

// Test fixtures: axios errors shaped like the ones the real adapters produce.

export interface HttpErrorOptions {
  data?: unknown;
  headers?: Record<string, string>;
  config?: InternalAxiosRequestConfig;
}

/** The error axios rejects with for a non-2xx HTTP response. */
export function httpError(status: number, { data, headers = {}, config }: HttpErrorOptions = {}): AxiosError {
  const requestConfig = config ?? { headers: new AxiosHeaders() };
  return new AxiosError(
    `Request failed with status code ${status}`,
    status >= 500 ? "ERR_BAD_RESPONSE" : "ERR_BAD_REQUEST",
    requestConfig,
    undefined,
    { status, statusText: "", headers, config: requestConfig, data },
  );
}

/** The error axios rejects with when no response arrived: a timeout or a network failure. */
export function noResponseError(code: "ETIMEDOUT" | "ERR_NETWORK"): AxiosError {
  const config = { headers: new AxiosHeaders() };
  return new AxiosError(code === "ETIMEDOUT" ? "timeout of 1000ms exceeded" : "Network Error", code, config);
}
