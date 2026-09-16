import { AxiosHeaders, type AxiosAdapter, type InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { httpError } from "../test/http";
import { api, refreshSession } from "./client";
import { listUsers, registerUser, updateUser } from "./users";

vi.mock("./client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./client")>()),
  refreshSession: vi.fn(),
}));

// Test fixture: a hand-written account, not data from a deployment.
const CREATED = {
  id: "8d0c7c1e-0000-4000-8000-000000000001",
  email: "new@example.com",
  role: "developer",
  is_active: true,
  created_at: "2026-09-15T10:00:00Z",
  permissions: ["scan:read"],
};

function ok(config: InternalAxiosRequestConfig, data: unknown) {
  return Promise.resolve({ data, status: 200, statusText: "OK", headers: {}, config });
}

describe("users API", () => {
  const originalAdapter = api.defaults.adapter;

  beforeEach(() => {
    vi.mocked(refreshSession).mockReset();
  });

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  it("sends list filters as query parameters, including an inactive filter", async () => {
    const adapter = vi.fn<AxiosAdapter>((config) => ok(config, { items: [], total: 0, limit: 25, offset: 0 }));
    api.defaults.adapter = adapter;

    await listUsers({ limit: 25, offset: 0, role: "auditor", is_active: false, q: "" });

    const config = adapter.mock.calls[0]?.[0];
    expect(config?.url).toBe("/users");
    expect(config?.params).toEqual({ limit: 25, offset: 0, role: "auditor", is_active: false });
  });

  it("encodes the user id and sends only the changed field", async () => {
    const adapter = vi.fn<AxiosAdapter>((config) => ok(config, CREATED));
    api.defaults.adapter = adapter;

    await updateUser("../audit", { is_active: false });

    const config = adapter.mock.calls[0]?.[0];
    expect(config?.method).toBe("patch");
    expect(config?.url).toBe("/users/..%2Faudit");
    expect(JSON.parse(String(config?.data))).toEqual({ is_active: false });
  });

  it("registers through /auth/register and retries once after refreshing an expired session", async () => {
    const adapter = vi
      .fn<AxiosAdapter>()
      .mockImplementationOnce((config) => Promise.reject(httpError(401, { config: { ...config, headers: new AxiosHeaders() } })))
      .mockImplementationOnce((config) => ok(config, CREATED));
    api.defaults.adapter = adapter;
    vi.mocked(refreshSession).mockResolvedValue("fresh-token");

    const body = { email: "new@example.com", password: "a long passphrase", role: "developer" as const };
    await expect(registerUser(body)).resolves.toEqual(CREATED);

    expect(refreshSession).toHaveBeenCalledOnce();
    expect(adapter).toHaveBeenCalledTimes(2);
    const config = adapter.mock.calls[1]?.[0];
    expect(config?.url).toBe("/auth/register");
    expect(JSON.parse(String(config?.data))).toEqual(body);
  });

  it("does not retry registration when the session was refused or the email is taken", async () => {
    const adapter = vi.fn<AxiosAdapter>((config) =>
      Promise.reject(httpError(401, { config: { ...config, headers: new AxiosHeaders() } })),
    );
    api.defaults.adapter = adapter;
    vi.mocked(refreshSession).mockResolvedValue(null);
    await expect(registerUser({ email: "a@example.com", password: "a long passphrase" })).rejects.toMatchObject({
      response: { status: 401 },
    });
    expect(adapter).toHaveBeenCalledOnce();

    vi.mocked(refreshSession).mockClear();
    api.defaults.adapter = vi.fn<AxiosAdapter>((config) =>
      Promise.reject(httpError(409, { config: { ...config, headers: new AxiosHeaders() } })),
    );
    await expect(registerUser({ email: "a@example.com", password: "a long passphrase" })).rejects.toMatchObject({
      response: { status: 409 },
    });
    expect(refreshSession).not.toHaveBeenCalled();
  });
});
