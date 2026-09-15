import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { getScan } from "../api/scans";
import type { Scan } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { SCRIPT_URL } from "../test/hostile";
import ScanDetail from "./ScanDetail";

vi.mock("../api/scans", () => ({
  getScan: vi.fn(),
  getScanReport: vi.fn(),
}));

// Test fixtures: hand-written scans in the v1 and Warden X response shapes, not real results.
const V1_SCAN: Scan = {
  id: "11111111-1111-4111-8111-111111111111",
  ecosystem: "pypi",
  package_name: "reqeusts",
  version: "1.0.0",
  rule_score: 92,
  ml_score: 88,
  risk_score: 95,
  severity: "critical",
  decision: "block",
  matched_policy_rules: ["block_threshold"],
  feature_vector: { install_hook: 1, network_calls: 3 },
  analyzer_version: "1.0.0",
  duration_ms: 420,
  created_at: "2026-09-01T10:00:00Z",
  signals: [
    {
      code: "INSTALL_HOOK_EXEC",
      severity: "critical",
      weight: 10,
      message: "setup.py runs code at install time",
      evidence: { snippet: "<script>alert(1)</script>" },
    },
  ],
};

const WARDEN_X_SCAN: Scan = {
  ...V1_SCAN,
  id: "22222222-2222-4222-8222-222222222222",
  environment: "production",
  model_version: "fixture-model",
  malicious_risk: 95,
  vulnerability_risk: null,
  signals: [
    {
      ...V1_SCAN.signals[0]!,
      finding_id: "f1",
      confidence: 0.9,
      category: "install_time_execution",
      title: "Install hook executes code",
      location: { file: "setup.py", line: 12 },
      cwe: ["CWE-94"],
      attack: ["T1195.002"],
    },
  ],
  policy_reasons: [{ rule: "block_threshold", detail: "Risk 95 is at or above 70", finding_ids: ["f1"] }],
  risk: {
    method: "warden-risk-2.0",
    final_score: 95,
    severity: "critical",
    confidence: 0.9,
    malicious_risk: 95,
    rule_score: 92,
    ml_score: 88,
    vulnerability_risk: null,
    dimensions: {
      behavioral: { score: 95, confidence: 0.9, contributors: ["f1"], rationale: "Install-time execution" },
      vulnerability: { score: null, confidence: 0, contributors: [], rationale: "Intelligence unavailable" },
    },
    floors_applied: [],
  },
  attack_chains: [
    {
      id: "c1",
      title: "Install-time execution chain",
      severity: "critical",
      confidence: 0.9,
      steps: [
        {
          order: 1,
          technique_id: "T1195.002",
          technique_name: "Compromise Software Supply Chain",
          tactic: "initial_access",
          finding_ids: ["f1"],
        },
      ],
    },
  ],
  vulnerabilities: [
    {
      id: "PYSEC-0000-FIXTURE",
      aliases: ["CVE-0000-00000"],
      summary: "Fixture advisory",
      severity: "high",
      cvss_score: 8.1,
      cvss_vector: null,
      cvss_version: "3.1",
      published: null,
      modified: null,
      affected_ranges: [],
      fixed_versions: ["1.0.1"],
      references: ["https://osv.dev/vulnerability/PYSEC-0000-FIXTURE", SCRIPT_URL],
      kev: true,
      kev_date_added: null,
      epss_score: 0.42,
      epss_percentile: 0.9,
      sources: ["osv"],
      withdrawn: null,
      database_specific_severity: null,
    },
  ],
  intel_status: { status: "ok", sources: { osv: "ok" } },
  provenance: { status: "unverified", attested: false, hash_verified: true, source_repository: "https://github.com/example/reqeusts" },
  analyzer_runs: [
    { name: "static_code", version: "2.0.0", status: "ok", duration_ms: 120, finding_count: 1, detail: null },
    { name: "semgrep", version: null, status: "unavailable", duration_ms: null, finding_count: 0, detail: "semgrep is not installed" },
  ],
};

function renderScan(scan: Scan) {
  vi.mocked(getScan).mockResolvedValue(scan);
  render(
    <AuthContext.Provider value={makeAuthState("security_analyst")}>
      <MemoryRouter initialEntries={[`/scans/${scan.id}`]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanDetail />} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("ScanDetail", () => {
  it("renders a v1 scan and says which Warden X data was not collected", async () => {
    const user = userEvent.setup();
    renderScan(V1_SCAN);

    expect(await screen.findByText("Block")).toBeInTheDocument();
    expect(vi.mocked(getScan)).toHaveBeenCalledWith(V1_SCAN.id, expect.anything());
    expect(screen.getByRole("meter", { name: "Final risk score" })).toHaveAttribute("aria-valuenow", "95");
    expect(screen.getByText(/recorded without Warden X analysis data/)).toBeInTheDocument();
    expect(screen.getByText("block_threshold")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "setup.py runs code at install time" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show evidence" }));
    expect(document.querySelector("script")).toBeNull();

    await user.click(screen.getByRole("tab", { name: "Risk breakdown" }));
    expect(screen.getByText("Risk dimensions were not recorded for this scan.")).toBeInTheDocument();
    expect(screen.getByText("network_calls")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Attack chains" }));
    expect(screen.getByText("Attack-chain correlation was not recorded for this scan.")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Vulnerabilities" }));
    expect(screen.getByText("Vulnerability intelligence was not recorded for this scan.")).toBeInTheDocument();
  });

  it("renders Warden X risk, chains, vulnerabilities, provenance and analyzer runs", async () => {
    const user = userEvent.setup();
    renderScan(WARDEN_X_SCAN);

    expect(await screen.findByRole("heading", { name: "Install hook executes code" })).toBeInTheDocument();
    expect(screen.queryByText(/recorded without Warden X analysis data/)).toBeNull();
    expect(screen.getByText("setup.py:12")).toBeInTheDocument();
    expect(screen.getByText("Risk 95 is at or above 70")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Risk breakdown" }));
    const dimensions = within(screen.getByRole("list", { name: "Risk dimensions" })).getAllByRole("listitem");
    expect(dimensions[1]).toHaveTextContent("unknown");

    await user.click(screen.getByRole("tab", { name: /Vulnerabilities/ }));
    expect(screen.getByText("In CISA KEV")).toBeInTheDocument();
    expect(screen.getByText("42.0%")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /osv.dev/ })).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.queryByRole("link", { name: /javascript/ })).toBeNull();

    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(screen.getByText("Hashes verified").nextElementSibling).toHaveTextContent("Yes");
    expect(screen.getByRole("link", { name: /github.com\/example\/reqeusts/ })).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /Analyzer runs/ }));
    expect(screen.getByText("Tool unavailable")).toBeInTheDocument();
    expect(screen.getByText("semgrep is not installed")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /Attack chains/ }));
    // The same finding is also linked from the policy reason in the Verdict card; use the chain's link.
    await user.click(within(screen.getByRole("tabpanel")).getByRole("link", { name: "INSTALL_HOOK_EXEC" }));
    expect(screen.getByRole("tab", { name: /Findings/ })).toHaveAttribute("aria-selected", "true");
    expect(document.getElementById("finding-f1")).toHaveFocus();
  });

  it("says the ML model was not available instead of showing its recorded 0 as a score", async () => {
    renderScan({
      ...WARDEN_X_SCAN,
      id: "33333333-3333-4333-8333-333333333333",
      ml_score: 0,
      model_version: null,
      explanation: { ml: { available: false, ml_score: 0, anomaly_score: 0 } },
      risk: { ...WARDEN_X_SCAN.risk!, ml_score: 0 },
    });

    expect(await screen.findByText("Model not available")).toBeInTheDocument();
    expect(screen.queryByRole("meter", { name: "ML model" })).toBeNull();
    expect(screen.getByRole("meter", { name: "Rule engine" })).toBeInTheDocument();
  });

  it("shows the server's error when the scan cannot be loaded", async () => {
    vi.mocked(getScan).mockRejectedValue(new Error("Scan not found"));
    render(
      <AuthContext.Provider value={makeAuthState("read_only")}>
        <MemoryRouter initialEntries={["/scans/missing"]}>
          <Routes>
            <Route path="/scans/:id" element={<ScanDetail />} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("Scan not found");
  });
});
