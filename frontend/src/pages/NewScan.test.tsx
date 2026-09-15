import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AxiosError } from "axios";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createScan } from "../api/scans";
import type { Role, Scan } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { httpError, noResponseError } from "../test/http";
import NewScan from "./NewScan";

vi.mock("../api/scans", () => ({ createScan: vi.fn() }));

// Test fixture: a hand-written scan result in the server's shape, not output from a real analysis.
const RESULT: Scan = {
  id: "44444444-4444-4444-8444-444444444444",
  ecosystem: "pypi",
  package_name: "requests",
  version: "2.32.3",
  rule_score: 12,
  ml_score: 0,
  risk_score: 12,
  severity: "info",
  decision: "allow",
  matched_policy_rules: [],
  feature_vector: {},
  analyzer_version: "2.0.0",
  duration_ms: 900,
  created_at: "2026-09-15T10:00:00Z",
  signals: [],
  model_version: null,
  explanation: { ml: { available: false, ml_score: 0 } },
};

function renderNewScan(role: Role) {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter>
        <NewScan />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

async function startScan(packageName: string) {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Package name"), packageName);
  await user.click(screen.getByRole("button", { name: "Start scan" }));
}

describe("NewScan", () => {
  beforeEach(() => {
    vi.mocked(createScan).mockReset();
  });

  it("tells a role without scan:create that it cannot start scans", () => {
    renderNewScan("auditor");
    expect(screen.getByText("Your role can review scans but not start them.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start scan" })).toBeNull();
  });

  it("starts a scan for a developer and does not present a missing model as a score", async () => {
    vi.mocked(createScan).mockResolvedValue(RESULT);
    renderNewScan("developer");
    await startScan("requests");

    expect(createScan).toHaveBeenCalledWith({ name: "requests", version: null, environment: "production" });
    expect(await screen.findByText("Scan complete")).toBeInTheDocument();
    expect(screen.getByText("ML score").nextElementSibling).toHaveTextContent("Model not available");
  });

  it.each<[string, AxiosError]>([
    ["the console stopped waiting", noResponseError("ETIMEDOUT")],
    ["the web server timed out", httpError(504, { data: "<html>504 Gateway Time-out</html>" })],
  ])("says the scan may still finish when %s", async (_case, failure) => {
    vi.mocked(createScan).mockRejectedValue(failure);
    renderNewScan("security_analyst");
    await startScan("big-sdist");

    expect(await screen.findByText("The scan result did not arrive in time")).toBeInTheDocument();
    expect(screen.queryByText("The scan did not complete")).toBeNull();
    expect(screen.getByRole("link", { name: "Check Scans for big-sdist" })).toHaveAttribute("href", "/scans?q=big-sdist");
  });

  it("reports other failures as a scan that did not complete", async () => {
    vi.mocked(createScan).mockRejectedValue(noResponseError("ERR_NETWORK"));
    renderNewScan("developer");
    await startScan("requests");

    expect(await screen.findByText("The scan did not complete")).toBeInTheDocument();
    expect(screen.getByText("Could not reach the Warden API. Check your connection.")).toBeInTheDocument();
  });
});
