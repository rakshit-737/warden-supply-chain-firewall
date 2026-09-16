import type { AxiosAdapter } from "axios";
import { afterEach, describe, expect, it, vi } from "vitest";
import { listAuditEvents, verifyAuditChain } from "./audit";
import { api } from "./client";

function adapterReturning(data: unknown) {
  return vi.fn<AxiosAdapter>((config) => Promise.resolve({ data, status: 200, statusText: "OK", headers: {}, config }));
}

describe("audit API", () => {
  const originalAdapter = api.defaults.adapter;

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  it("lists with the backend's filter names", async () => {
    const adapter = adapterReturning({ items: [], total: 0, limit: 25, offset: 0 });
    api.defaults.adapter = adapter;

    await listAuditEvents({ limit: 25, offset: 0, action: "policy.update", actor_id: "", target_type: "policy" });

    const config = adapter.mock.calls[0]?.[0];
    expect(config?.url).toBe("/audit");
    expect(config?.params).toEqual({ limit: 25, offset: 0, action: "policy.update", target_type: "policy" });
  });

  it("verifies the chain with a GET", async () => {
    const adapter = adapterReturning({ ok: true, checked: 3, verified_at: "2026-09-15T12:00:00Z" });
    api.defaults.adapter = adapter;

    const result = await verifyAuditChain();

    const config = adapter.mock.calls[0]?.[0];
    expect(config?.method).toBe("get");
    expect(config?.url).toBe("/audit/verify");
    expect(result.checked).toBe(3);
  });
});
