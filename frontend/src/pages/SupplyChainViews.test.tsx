import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createContainerScan, getContainerScan, listContainerScans } from "../api/containers";
import { createDiff, getDiff, listDiffs } from "../api/diffs";
import {
  addMonitoredPackage,
  checkMonitoredPackage,
  listMonitoredPackages,
  removeMonitoredPackage,
  updateMonitoredPackage,
} from "../api/monitoring";
import { getPackage } from "../api/packages";
import type { ContainerScan, MonitoredPackage, PackageOverview, ReleaseDiff, Role } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import ContainerDetail from "./ContainerDetail";
import Containers from "./Containers";
import DiffDetail from "./DiffDetail";
import Diffs from "./Diffs";
import Monitoring from "./Monitoring";
import Packages from "./Packages";

vi.mock("../api/diffs", () => ({ createDiff: vi.fn(), getDiff: vi.fn(), listDiffs: vi.fn() }));
vi.mock("../api/containers", () => ({
  createContainerScan: vi.fn(),
  getContainerScan: vi.fn(),
  getContainerScanSbom: vi.fn(),
  listContainerScans: vi.fn(),
}));
vi.mock("../api/monitoring", () => ({
  addMonitoredPackage: vi.fn(),
  checkMonitoredPackage: vi.fn(),
  listMonitoredPackages: vi.fn(),
  removeMonitoredPackage: vi.fn(),
  updateMonitoredPackage: vi.fn(),
}));
vi.mock("../api/packages", () => ({ getPackage: vi.fn() }));

// Test fixtures: hand-written, not data from a deployment.
const DIFF: ReleaseDiff = {
  id: "d-1",
  ecosystem: "pypi",
  package: "demo",
  old_version: "1.0.0",
  new_version: "2.0.0",
  analyzer_version: "2.0.0",
  drift_detected: true,
  drift_score: 65,
  created_at: "2026-09-02T10:00:00Z",
  summary: {
    ecosystem: "pypi",
    name: "demo",
    from_version: "1.0.0",
    to_version: "2.0.0",
    verdict: "escalated",
    reasons: ["new capabilities: network_egress"],
    risk: { from: 5, to: 70, delta: 65, from_severity: "info", to_severity: "high", dimensions: { behavioral: { from: 0, to: 60, delta: 60 } } },
    capabilities: { added: ["network_egress"], removed: [] },
    files: {
      available: true, added: ["demo/_x.so"], removed: [], changed: ["setup.py"], added_count: 1, removed_count: 0,
      changed_count: 1, new_executable_binaries: ["demo/_x.so"], install_time_changes: ["setup.py"],
    },
    maintainers: { available: true, added: ["eve"], removed: [] },
  },
  findings: [{ code: "NETWORK_EGRESS", severity: "high", file: "demo/__init__.py", line: 4, message: "posts to a host" }],
};

const IMAGE: ContainerScan = {
  id: "c-1",
  image_ref: "demo:1.0",
  image_digest: "sha256:" + "a".repeat(64),
  created_at: "2026-09-02T10:00:00Z",
  status: "incomplete",
  decision: "warn",
  risk_score: 35,
  tools: { trivy: { name: "trivy", status: "unavailable", version: null, detail: "not found", vulnerabilities: 0, truncated: false } },
  summary: {
    image_refs: ["demo:1.0"], os: "linux", architecture: "amd64", user: "", layer_count: 2,
    component_counts: { apk: 2 }, reasons: ["the image could not be analysed completely"], warnings: ["layer 1: 3 file(s) were not read"],
  },
  findings: [{ code: "DOCKERFILE_ROOT_USER", severity: "medium", weight: 1, message: "The image runs as root", evidence: {} }],
};

const WATCHED: MonitoredPackage = {
  id: "m-1",
  ecosystem: "pypi",
  name: "requests",
  approved_version: "2.32.3",
  latest_seen_version: "2.33.0",
  enabled: true,
  poll_interval_seconds: 3600,
  last_checked_at: "2026-09-02T10:00:00Z",
  next_check_at: null,
  last_risk_score: 12,
  snapshot: null,
  project_id: null,
  consecutive_failures: 0,
  created_at: "2026-09-01T10:00:00Z",
};

function renderAt(path: string, role: Role) {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/diffs" element={<Diffs />} />
          <Route path="/diffs/:id" element={<DiffDetail />} />
          <Route path="/containers" element={<Containers />} />
          <Route path="/containers/:id" element={<ContainerDetail />} />
          <Route path="/monitoring" element={<Monitoring />} />
          <Route path="/packages" element={<Packages />} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(listDiffs).mockResolvedValue({ items: [DIFF], total: 1, limit: 25, offset: 0 });
  vi.mocked(getDiff).mockResolvedValue(DIFF);
  vi.mocked(listContainerScans).mockResolvedValue({ items: [IMAGE], total: 1, limit: 25, offset: 0 });
  vi.mocked(getContainerScan).mockResolvedValue(IMAGE);
  vi.mocked(listMonitoredPackages).mockResolvedValue({ items: [WATCHED], total: 1, limit: 50, offset: 0 });
});

describe("Release diffs", () => {
  it("compares two releases and opens the result", async () => {
    vi.mocked(createDiff).mockResolvedValue(DIFF);
    renderAt("/diffs", "developer");
    expect(await screen.findByRole("link", { name: /demo 1.0.0 → 2.0.0/ })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("PyPI package"), "demo");
    await userEvent.type(screen.getByLabelText("From version"), "1.0.0");
    await userEvent.type(screen.getByLabelText("To version"), "2.0.0");
    await userEvent.click(screen.getByRole("button", { name: "Compare" }));
    await waitFor(() => expect(createDiff).toHaveBeenCalledWith({ name: "demo", from_version: "1.0.0", to_version: "2.0.0" }));
    expect(await screen.findByText("Why this counts as drift")).toBeInTheDocument();
  });

  it("filters to drift and hides the form from auditors", async () => {
    renderAt("/diffs", "auditor");
    await screen.findByRole("link", { name: /demo/ });
    expect(screen.queryByRole("button", { name: "Compare" })).toBeNull();
    await userEvent.click(screen.getByLabelText("Only comparisons with drift"));
    await waitFor(() => expect(listDiffs).toHaveBeenLastCalledWith(expect.objectContaining({ drift_only: true }), expect.anything()));
  });

  it("shows risk, capability, file and maintainer changes", async () => {
    renderAt("/diffs/d-1", "read_only");
    expect(await screen.findByText("new capabilities: network_egress")).toBeInTheDocument();
    expect(screen.getByText("5 (info) → 70 (high)")).toBeInTheDocument();
    expect(screen.getAllByText("demo/_x.so").length).toBeGreaterThan(0);
    expect(screen.getByText("eve")).toBeInTheDocument();
    expect(within(screen.getByRole("table", { name: "New findings in the newer release" })).getByText("demo/__init__.py:4")).toBeInTheDocument();
  });

  it("says when files could not be compared", async () => {
    vi.mocked(getDiff).mockResolvedValue({
      ...DIFF,
      summary: { ...DIFF.summary!, files: { available: false, reason: "file inventory missing for one release" } },
    });
    renderAt("/diffs/d-1", "admin");
    expect(await screen.findByText("File comparison unavailable: file inventory missing for one release.")).toBeInTheDocument();
  });
});

describe("Containers", () => {
  it("uploads an archive as raw bytes and opens the scan", async () => {
    vi.mocked(createContainerScan).mockResolvedValue(IMAGE);
    renderAt("/containers", "developer");
    await screen.findByRole("link", { name: "demo:1.0" });
    const archive = new File([new Uint8Array([1, 2, 3])], "image.tar", { type: "application/x-tar" });
    await userEvent.upload(screen.getByLabelText("Image archive (.tar)"), archive);
    await userEvent.type(screen.getByLabelText("Label (optional)"), "demo:1.0");
    await userEvent.click(screen.getByRole("button", { name: "Scan image" }));
    await waitFor(() =>
      expect(createContainerScan).toHaveBeenCalledWith({ archive, imageRef: "demo:1.0", vulnerabilities: true }),
    );
    expect(await screen.findByText("Analysis incomplete")).toBeInTheDocument();
  });

  it("never presents an unassessed or incomplete image as clean", async () => {
    renderAt("/containers/c-1", "read_only");
    expect(await screen.findByText("Not assessed: Trivy is not installed on the server")).toBeInTheDocument();
    expect(screen.getByText("Analysis incomplete")).toBeInTheDocument();
    expect(screen.getByText("root (not set)")).toBeInTheDocument();
    expect(screen.getByText("layer 1: 3 file(s) were not read")).toBeInTheDocument();
  });

  it("hides the upload from roles without container:scan", async () => {
    renderAt("/containers", "auditor");
    await screen.findByRole("link", { name: "demo:1.0" });
    expect(screen.queryByRole("button", { name: "Scan image" })).toBeNull();
  });
});

describe("Monitoring", () => {
  it("adds, checks, pauses and removes watched packages", async () => {
    vi.mocked(addMonitoredPackage).mockResolvedValue(WATCHED);
    vi.mocked(checkMonitoredPackage).mockResolvedValue({
      package: "requests", status: "new_release", version: "2.33.0", diff_id: "d-9", detail: null,
    });
    vi.mocked(updateMonitoredPackage).mockResolvedValue({ ...WATCHED, enabled: false });
    vi.mocked(removeMonitoredPackage).mockResolvedValue();
    renderAt("/monitoring", "security_analyst");
    await screen.findByRole("link", { name: "requests" });

    await userEvent.type(screen.getByLabelText("PyPI package"), "flask");
    await userEvent.click(screen.getByRole("button", { name: "Watch" }));
    await waitFor(() =>
      expect(addMonitoredPackage).toHaveBeenCalledWith({ name: "flask", approved_version: null, poll_interval_seconds: 3600 }),
    );

    await userEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await screen.findByText(/requests: New release analysed \(2\.33\.0\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View comparison" })).toHaveAttribute("href", "/diffs/d-9");

    await userEvent.click(screen.getByRole("button", { name: "Pause" }));
    await waitFor(() => expect(updateMonitoredPackage).toHaveBeenCalledWith("m-1", { enabled: false }));
    await userEvent.click(screen.getByRole("button", { name: "Stop watching requests" }));
    await waitFor(() => expect(removeMonitoredPackage).toHaveBeenCalledWith("m-1"));
  });

  it("is read-only for developers and highlights failing checks", async () => {
    vi.mocked(listMonitoredPackages).mockResolvedValue({
      items: [{ ...WATCHED, consecutive_failures: 3 }], total: 1, limit: 50, offset: 0,
    });
    renderAt("/monitoring", "developer");
    expect(await screen.findByText("3 failed in a row")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Watch" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Check now" })).toBeNull();
  });

  it("reports a failed action", async () => {
    vi.mocked(checkMonitoredPackage).mockRejectedValue(httpError(502, { data: { error: { code: "bad_gateway", message: "registry down" } } }));
    renderAt("/monitoring", "admin");
    await userEvent.click(await screen.findByRole("button", { name: "Check now" }));
    expect(await screen.findByText("The action did not complete")).toBeInTheDocument();
  });
});

describe("Packages", () => {
  const OVERVIEW: PackageOverview = {
    ecosystem: "pypi",
    name: "requests",
    latest_verdict: {
      scan_id: "s-1", version: "2.32.3", environment: "production", decision: "block", risk_score: 88,
      severity: "critical", scanned_at: "2026-09-02T10:00:00Z", package_intel: null, provenance: null,
    },
    verdicts: [{ scan_id: "s-1", version: "2.32.3", environment: "production", decision: "block", risk_score: 88, severity: "critical", scanned_at: "2026-09-02T10:00:00Z" }],
    vulnerabilities: [{ id: "GHSA-test", severity: "critical", kev: true, versions: ["2.32.3"] }],
    monitoring: [],
    release_diffs: [{ id: "d-1", old_version: "2.32.3", new_version: "2.33.0", drift_detected: false, drift_score: 0, created_at: "2026-09-02T10:00:00Z" }],
  };

  it("looks up a package and shows its history", async () => {
    vi.mocked(getPackage).mockResolvedValue(OVERVIEW);
    renderAt("/packages", "read_only");
    await userEvent.type(screen.getByLabelText("PyPI package name"), "requests");
    await userEvent.click(screen.getByRole("button", { name: "Look up" }));
    expect(await screen.findByText(/GHSA-test/)).toBeInTheDocument();
    expect(getPackage).toHaveBeenCalledWith("pypi", "requests", expect.anything());
    expect(screen.getByRole("link", { name: "2.32.3" })).toHaveAttribute("href", "/scans/s-1");
    expect(screen.getByRole("link", { name: "2.32.3 → 2.33.0" })).toHaveAttribute("href", "/diffs/d-1");
    expect(screen.getByText(/known exploited/)).toBeInTheDocument();
  });

  it("explains an unknown package and rejects invalid names without a request", async () => {
    vi.mocked(getPackage).mockRejectedValue(httpError(404, { data: { error: { code: "not_found", message: "no data" } } }));
    renderAt("/packages?name=unknown-pkg", "admin");
    expect(await screen.findByText("Warden has no data for this package yet.")).toBeInTheDocument();
  });

  it("does not call the API for an invalid name", async () => {
    renderAt("/packages?name=..%2Fetc", "admin");
    expect(await screen.findByText("Invalid name")).toBeInTheDocument();
    expect(getPackage).not.toHaveBeenCalled();
  });
});
