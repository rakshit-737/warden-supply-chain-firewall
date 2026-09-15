import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listScans } from "../api/scans";
import type { ListScansParams, Page, ScanSummary } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import Scans from "./Scans";

vi.mock("../api/scans", () => ({ listScans: vi.fn() }));

// Test fixture: 30 hand-written scan summaries, not real results.
const ALL: ScanSummary[] = Array.from({ length: 30 }, (_, index) => ({
  id: `scan-${index}`,
  ecosystem: "pypi",
  package_name: `package-${index}`,
  version: "1.0.0",
  risk_score: 10,
  severity: "info",
  decision: "allow",
  created_at: "2026-09-15T10:00:00Z",
  environment: "production",
}));

/** Behaves like the server: the requested offset is not clamped, so past the end there are no items. */
function pageFor(params: ListScansParams = {}): Page<ScanSummary> {
  const limit = params.limit ?? 25;
  const offset = params.offset ?? 0;
  return { items: ALL.slice(offset, offset + limit), total: ALL.length, limit, offset };
}

function LocationProbe() {
  return <output aria-label="Current search">{useLocation().search}</output>;
}

function renderScans(path: string) {
  render(
    <AuthContext.Provider value={makeAuthState("developer")}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <>
                <Scans />
                <LocationProbe />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("Scans", () => {
  beforeEach(() => {
    vi.mocked(listScans)
      .mockReset()
      .mockImplementation((params) => Promise.resolve(pageFor(params)));
  });

  it("moves an offset past the end to the last page instead of claiming there are no scans", async () => {
    renderScans("/scans?offset=100");

    // Two request round trips (the out-of-range page, then the last page): allow more than the default
    // one second, which is not always enough while the whole suite runs in parallel.
    await waitFor(() => expect(screen.getByLabelText("Current search")).toHaveTextContent("?offset=25"), { timeout: 5000 });
    expect(await screen.findByRole("link", { name: /package-25/ }, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.queryByText("No scans yet.")).toBeNull();
    expect(listScans).toHaveBeenCalledWith(expect.objectContaining({ offset: 100 }), expect.anything());
  });

  it("still says there are no scans when the deployment has none", async () => {
    vi.mocked(listScans).mockResolvedValue({ items: [], total: 0, limit: 25, offset: 0 });
    renderScans("/scans");
    expect(await screen.findByText("No scans yet.")).toBeInTheDocument();
  });
});
