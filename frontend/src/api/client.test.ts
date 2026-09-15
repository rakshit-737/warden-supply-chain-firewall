import axios, { type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { httpError, noResponseError } from "../test/http";
import {
  api,
  CLIENT_TIMEOUT_CODE,
  cleanParams,
  isSessionRejection,
  pathSegment,
  refreshSession,
  registerLogoutHandler,
  setAccessToken,
  toApiError,
} from "./client";

// Test fixture: a token response in the server's shape; the token is not a real credential.
const TOKENS = { data: { access_token: "fresh-token", token_type: "bearer", expires_in: 900 } };

describe("pathSegment", () => {
  it("percent-encodes separators so an id cannot address another endpoint", () => {
    expect(pathSegment("../users")).toBe("..%2Fusers");
    expect(pathSegment("a/b?c#d")).toBe("a%2Fb%3Fc%23d");
    expect(pathSegment(42)).toBe("42");
  });

  it("rejects empty and dot segments", () => {
    expect(() => pathSegment("")).toThrow();
    expect(() => pathSegment(".")).toThrow();
    expect(() => pathSegment("..")).toThrow();
  });
});

describe("cleanParams", () => {
  it("drops empty values instead of sending them as literal strings", () => {
    expect(cleanParams({ q: "", decision: undefined, severity: null, limit: 25, offset: 0 })).toEqual({ limit: 25, offset: 0 });
  });
});

describe("isSessionRejection", () => {
  it("counts only definitive refusals as a lost session", () => {
    for (const status of [400, 401, 403]) expect(isSessionRejection(httpError(status))).toBe(true);
    for (const status of [408, 429, 500, 502, 503, 504]) expect(isSessionRejection(httpError(status))).toBe(false);
    expect(isSessionRejection(noResponseError("ERR_NETWORK"))).toBe(false);
    expect(isSessionRejection(noResponseError("ETIMEDOUT"))).toBe(false);
    expect(isSessionRejection(new Error("unexpected"))).toBe(false);
  });
});

describe("refreshSession", () => {
  it("sends one refresh request for concurrent callers", async () => {
    const post = vi.spyOn(axios, "post").mockResolvedValue(TOKENS);
    const [first, second] = await Promise.all([refreshSession(), refreshSession()]);
    expect(first).toBe("fresh-token");
    expect(second).toBe("fresh-token");
    expect(post).toHaveBeenCalledTimes(1);
  });

  it("resolves to null when the server refuses the refresh cookie", async () => {
    vi.spyOn(axios, "post").mockRejectedValue(httpError(401));
    await expect(refreshSession()).resolves.toBeNull();
  });

  it("rejects instead of reporting no session when the server could not answer", async () => {
    const post = vi.spyOn(axios, "post");
    post.mockRejectedValueOnce(httpError(429, { headers: { "retry-after": "20" } }));
    await expect(refreshSession()).rejects.toMatchObject({ response: { status: 429 } });
    post.mockRejectedValueOnce(httpError(502));
    await expect(refreshSession()).rejects.toMatchObject({ response: { status: 502 } });
    post.mockRejectedValueOnce(noResponseError("ERR_NETWORK"));
    await expect(refreshSession()).rejects.toMatchObject({ code: "ERR_NETWORK" });
  });
});

describe("401 handling in the API client", () => {
  const originalAdapter = api.defaults.adapter;
  const adapter = vi.fn<AxiosAdapter>();
  const onLogout = vi.fn();

  beforeEach(() => {
    adapter.mockReset();
    onLogout.mockReset();
    api.defaults.adapter = adapter;
    setAccessToken("expired-token");
    registerLogoutHandler(onLogout);
  });

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
    setAccessToken(null);
    registerLogoutHandler(null);
  });

  function reply(config: InternalAxiosRequestConfig, data: unknown): Promise<AxiosResponse> {
    return Promise.resolve({ data, status: 200, statusText: "OK", headers: {}, config });
  }

  it("refreshes once and retries the request with the new token", async () => {
    const post = vi.spyOn(axios, "post").mockResolvedValue(TOKENS);
    const bearers: unknown[] = [];
    adapter.mockImplementation((config) => {
      bearers.push(config.headers.get("Authorization"));
      return config.headers.get("Authorization") === "Bearer fresh-token"
        ? reply(config, { ok: true })
        : Promise.reject(httpError(401, { config }));
    });

    await expect(api.get("/scans")).resolves.toMatchObject({ data: { ok: true } });
    expect(post).toHaveBeenCalledOnce();
    expect(bearers).toEqual(["Bearer expired-token", "Bearer fresh-token"]);
    expect(onLogout).not.toHaveBeenCalled();
  });

  it("signs the user out when the server refuses the refresh", async () => {
    vi.spyOn(axios, "post").mockRejectedValue(httpError(401));
    adapter.mockImplementation((config) => Promise.reject(httpError(401, { config })));

    await expect(api.get("/scans")).rejects.toMatchObject({ response: { status: 401 } });
    expect(onLogout).toHaveBeenCalledOnce();
    expect(adapter).toHaveBeenCalledOnce();
  });

  it("keeps the session when the refresh is rate limited, and reports the wait", async () => {
    vi.spyOn(axios, "post").mockRejectedValue(httpError(429, { headers: { "retry-after": "30" } }));
    adapter.mockImplementation((config) => Promise.reject(httpError(401, { config })));

    const failure: unknown = await api.get("/scans").catch((err: unknown) => err);
    expect(toApiError(failure)).toMatchObject({ status: 429, retryAfterSeconds: 30 });
    expect(onLogout).not.toHaveBeenCalled();
  });

  it("keeps the session when the refresh cannot reach the server", async () => {
    vi.spyOn(axios, "post").mockRejectedValue(noResponseError("ERR_NETWORK"));
    adapter.mockImplementation((config) => Promise.reject(httpError(401, { config })));

    await expect(api.get("/scans")).rejects.toMatchObject({ code: "ERR_NETWORK" });
    expect(onLogout).not.toHaveBeenCalled();
  });

  it("never refreshes for authentication endpoints", async () => {
    const post = vi.spyOn(axios, "post").mockRejectedValue(httpError(401));
    adapter.mockImplementation((config) => Promise.reject(httpError(401, { config })));

    await expect(api.post("/auth/login", { email: "a@example.test", password: "wrong" })).rejects.toMatchObject({
      response: { status: 401 },
    });
    expect(post).not.toHaveBeenCalled();
    expect(onLogout).not.toHaveBeenCalled();
  });

  it("refreshes at most once when the retried request is refused again", async () => {
    const post = vi.spyOn(axios, "post").mockResolvedValue(TOKENS);
    adapter.mockImplementation((config) => Promise.reject(httpError(401, { config })));

    await expect(api.get("/scans")).rejects.toMatchObject({ response: { status: 401 } });
    expect(post).toHaveBeenCalledOnce();
    expect(adapter).toHaveBeenCalledTimes(2);
  });
});

describe("toApiError", () => {
  it("reads the server's error envelope", () => {
    const error = toApiError(
      httpError(403, { data: { error: { code: "forbidden", message: "Missing permission scan:create", request_id: "req-7" } } }),
    );
    expect(error).toEqual({
      status: 403,
      code: "forbidden",
      message: "Missing permission scan:create",
      requestId: "req-7",
      retryAfterSeconds: null,
    });
  });

  it("falls back to a status message when the body is not an envelope", () => {
    expect(toApiError(httpError(429, { data: "<html>busy</html>" })).message).toBe("Too many requests. Wait a moment and try again.");
    expect(toApiError(httpError(504, { data: "<html>Gateway Time-out</html>" })).message).toMatch(/may still be processed/);
  });

  it("reads Retry-After as seconds or as an HTTP date", () => {
    expect(toApiError(httpError(429, { headers: { "Retry-After": "45" } })).retryAfterSeconds).toBe(45);
    const inNinetySeconds = new Date(Date.now() + 90_000).toUTCString();
    const fromDate = toApiError(httpError(429, { headers: { "retry-after": inNinetySeconds } })).retryAfterSeconds;
    expect(fromDate).toBeGreaterThanOrEqual(88);
    expect(fromDate).toBeLessThanOrEqual(90);
    expect(toApiError(httpError(429, { headers: { "retry-after": "soon" } })).retryAfterSeconds).toBeNull();
  });

  it("marks a client-side timeout separately from an unreachable server", () => {
    expect(toApiError(noResponseError("ETIMEDOUT"))).toMatchObject({ status: null, code: CLIENT_TIMEOUT_CODE });
    expect(toApiError(noResponseError("ERR_NETWORK"))).toMatchObject({
      status: null,
      code: null,
      message: "Could not reach the Warden API. Check your connection.",
    });
  });

  it("configures timeouts to be recognisable without dropping JSON parsing", () => {
    expect(api.defaults.transitional).toMatchObject({
      clarifyTimeoutError: true,
      forcedJSONParsing: true,
      silentJSONParsing: true,
    });
  });
});
