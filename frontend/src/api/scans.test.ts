import type { AxiosAdapter } from "axios";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";
import { createScan, SCAN_REQUEST_TIMEOUT_MS } from "./scans";

describe("createScan", () => {
  const originalAdapter = api.defaults.adapter;

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  it("waits longer than the server's scan limit and the web server's read timeout", async () => {
    const adapter = vi.fn<AxiosAdapter>((config) =>
      Promise.resolve({ data: { id: "scan-1" }, status: 200, statusText: "OK", headers: {}, config }),
    );
    api.defaults.adapter = adapter;

    await createScan({ name: "requests", version: null, environment: "production" });

    const config = adapter.mock.calls[0]?.[0];
    expect(config?.url).toBe("/scans");
    expect(config?.timeout).toBe(SCAN_REQUEST_TIMEOUT_MS);
    // SCAN_TIMEOUT_SECONDS defaults to 180 s; nginx proxy_read_timeout is 210 s.
    expect(SCAN_REQUEST_TIMEOUT_MS).toBeGreaterThan(210_000);
    expect(JSON.parse(String(config?.data))).toEqual({
      ecosystem: "pypi",
      name: "requests",
      version: null,
      environment: "production",
    });
  });
});
