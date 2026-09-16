import type { AxiosAdapter } from "axios";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";
import { acknowledgeEvent, listEvents } from "./events";

function adapterReturning(data: unknown) {
  return vi.fn<AxiosAdapter>((config) => Promise.resolve({ data, status: 200, statusText: "OK", headers: {}, config }));
}

describe("events API", () => {
  const originalAdapter = api.defaults.adapter;

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  it("sends the backend's query names and leaves out empty filters", async () => {
    const adapter = adapterReturning({ items: [], total: 0, limit: 25, offset: 0 });
    api.defaults.adapter = adapter;

    await listEvents({
      limit: 25,
      offset: 50,
      type: "package_blocked",
      severity: "high",
      package: "",
      project_id: undefined,
      since: "2026-09-01T00:00:00.000Z",
      acknowledged: false,
    });

    const config = adapter.mock.calls[0]?.[0];
    expect(config?.method).toBe("get");
    expect(config?.url).toBe("/events");
    expect(config?.params).toEqual({
      limit: 25,
      offset: 50,
      type: "package_blocked",
      severity: "high",
      since: "2026-09-01T00:00:00.000Z",
      acknowledged: false,
    });
  });

  it("acknowledges through an encoded path segment and refuses dot segments", async () => {
    const adapter = adapterReturning({ id: "a/b", acknowledged: true });
    api.defaults.adapter = adapter;

    await acknowledgeEvent("a/b");

    const config = adapter.mock.calls[0]?.[0];
    expect(config?.method).toBe("post");
    expect(config?.url).toBe("/events/a%2Fb/ack");
    await expect(acknowledgeEvent("..")).rejects.toThrow("Invalid identifier");
    expect(adapter).toHaveBeenCalledOnce();
  });
});
