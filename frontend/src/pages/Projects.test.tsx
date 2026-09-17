import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createProject,
  createProjectScan,
  getProject,
  getProjectScan,
  getProjectScanGraph,
  getProjectScanSbom,
  listProjectScanComponents,
  listProjectScans,
  listProjects,
} from "../api/projects";
import type { GraphAnalysis, Project, ProjectScan, Role } from "../api/types";
import { AuthContext } from "../auth/context";
import { downloadText } from "../lib/download";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import ProjectDetail from "./ProjectDetail";
import Projects from "./Projects";
import ProjectScanDetail from "./ProjectScanDetail";

vi.mock("../api/projects", () => ({
  createProject: vi.fn(),
  createProjectScan: vi.fn(),
  getProject: vi.fn(),
  getProjectScan: vi.fn(),
  getProjectScanGraph: vi.fn(),
  getProjectScanSbom: vi.fn(),
  listProjectScanComponents: vi.fn(),
  listProjectScans: vi.fn(),
  listProjects: vi.fn(),
}));
vi.mock("../lib/download", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/download")>()),
  downloadText: vi.fn(),
}));

// Test fixtures: hand-written, not data from a deployment.
const PROJECT: Project = {
  id: "p-1",
  name: "payments-api",
  description: "Card processing",
  created_at: "2026-09-01T10:00:00Z",
  updated_at: "2026-09-02T10:00:00Z",
};
const SCAN: ProjectScan = {
  id: "ps-1",
  project_id: "p-1",
  created_at: "2026-09-02T10:00:00Z",
  component_count: 2,
  direct_count: 2,
  decision: "warn",
  risk_score: 35,
  environment: "production",
  manifests: [{ file: "requirements.txt", type: "requirements" }],
  summary: {
    findings: [
      {
        code: "INDEX_SOURCE_AMBIGUITY",
        severity: "medium",
        weight: 1,
        message: "--extra-index-url adds a second package index <img src=x onerror=alert(1)>",
        evidence: {},
        location: { file: "requirements.txt", line: 1 },
      },
    ],
    warnings: ["line 3: could not parse"],
    components_with_verdict: 1,
  },
  policy_reasons: [],
};
const GRAPH: GraphAnalysis = {
  nodes: [
    {
      id: "pkg:flask", type: "package", name: "flask", version: "3.0.0", direct: true, depth: 1, risk: 10,
      severity: "low", decision: "allow", dependents: 1, transitive_dependents: 1, transitive_dependencies: 0,
      blast_radius: 0.5, direct_exposure: null, dominated: null, betweenness: null, is_single_point: true,
      vulnerability_ids: [], findings_count: null, subtree_max_risk: null,
    },
  ],
  edges: [],
  metrics: {
    node_count: 2, edge_count: 1, max_depth: 1, direct_count: 1, transitive_count: 0, has_cycles: false,
    single_points: [{}], high_risk_transitive: [],
  },
};

function renderAt(path: string, role: Role) {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/projects" element={<Projects />} />
          <Route path="/projects/:id" element={<ProjectDetail />} />
          <Route path="/projects/:id/scans/:scanId" element={<ProjectScanDetail />} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("Projects", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(listProjects).mockResolvedValue({ items: [PROJECT], total: 1, limit: 25, offset: 0 });
    vi.mocked(getProject).mockResolvedValue(PROJECT);
    vi.mocked(listProjectScans).mockResolvedValue({ items: [SCAN], total: 1, limit: 20, offset: 0 });
    vi.mocked(getProjectScan).mockResolvedValue(SCAN);
    vi.mocked(getProjectScanGraph).mockResolvedValue(GRAPH);
    vi.mocked(listProjectScanComponents).mockResolvedValue({
      items: [{
        bom_ref: "pkg:pypi/flask@3.0.0", name: "flask", version: "3.0.0", purl: null, direct: true, depth: 1,
        scope: "required", resolution: "pinned", declared_at: [{ file: "requirements.txt", line: 2 }],
        introduced_by: null, scan_id: "s-1", risk_score: 10, decision: "allow", vulnerability_count: 0,
      }],
      total: 1, limit: 100, offset: 0,
    });
  });

  it("lists projects and creates one for engineers", async () => {
    vi.mocked(createProject).mockResolvedValue({ ...PROJECT, id: "p-new", name: "new-app" });
    renderAt("/projects", "developer");
    expect(await screen.findByRole("link", { name: "payments-api" })).toHaveAttribute("href", "/projects/p-1");
    await userEvent.type(screen.getByLabelText("Name"), "new-app");
    await userEvent.click(screen.getByRole("button", { name: "Create project" }));
    await waitFor(() => expect(createProject).toHaveBeenCalledWith({ name: "new-app", description: null }));
    expect(await screen.findByRole("heading", { name: "payments-api" })).toBeInTheDocument();
  });

  it("hides project creation from read-only roles", async () => {
    renderAt("/projects", "read_only");
    await screen.findByRole("link", { name: "payments-api" });
    expect(screen.queryByRole("button", { name: "Create project" })).toBeNull();
  });

  it("shows a server rejection of a duplicate project", async () => {
    vi.mocked(createProject).mockRejectedValue(
      httpError(409, { data: { error: { code: "conflict", message: "A project with this name already exists" } } }),
    );
    renderAt("/projects", "admin");
    await userEvent.type(await screen.findByLabelText("Name"), "payments-api");
    await userEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(await screen.findByText("The project was not created")).toBeInTheDocument();
  });

  it("submits pasted and uploaded manifests, then opens the scan", async () => {
    vi.mocked(createProjectScan).mockResolvedValue(SCAN);
    renderAt("/projects/p-1", "security_analyst");
    await screen.findByRole("heading", { name: "payments-api" });
    const file = new File(["flask==3.0.0\n"], "requirements-dev.txt", { type: "text/plain" });
    await userEvent.upload(screen.getByLabelText(/Manifest files/), file);
    await screen.findByText(/1 file\(s\): requirements-dev.txt/);
    await userEvent.type(screen.getByLabelText("Or paste a manifest"), "requests==2.33.0");
    await userEvent.click(screen.getByRole("button", { name: "Scan" }));
    await waitFor(() =>
      expect(createProjectScan).toHaveBeenCalledWith("p-1", {
        files: { "requirements-dev.txt": "flask==3.0.0\n", "requirements.txt": "requests==2.33.0" },
        environment: "production",
      }),
    );
    expect(await screen.findByRole("heading", { name: "Project scan" })).toBeInTheDocument();
  });

  it("refuses an empty scan and oversized files before sending anything", async () => {
    renderAt("/projects/p-1", "developer");
    await screen.findByRole("heading", { name: "payments-api" });
    await userEvent.click(screen.getByRole("button", { name: "Scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Paste a manifest or choose manifest files first.");
    const big = new File(["x"], "huge.txt");
    Object.defineProperty(big, "size", { value: 2_000_000 });
    await userEvent.upload(screen.getByLabelText(/Manifest files/), big);
    expect(await screen.findByRole("alert")).toHaveTextContent("huge.txt is larger than");
    expect(createProjectScan).not.toHaveBeenCalled();
  });

  it("shows scan findings as text, components, the graph and exports SBOMs", async () => {
    vi.mocked(getProjectScanSbom).mockResolvedValue('{"bomFormat":"CycloneDX"}');
    renderAt("/projects/p-1/scans/ps-1", "auditor");
    expect(await screen.findByText(/adds a second package index <img/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("line 3: could not parse")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: /Components/ }));
    const row = await screen.findByRole("row", { name: /flask/ });
    expect(within(row).getByText("requirements.txt:2")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: /Dependency graph/ }));
    expect(await screen.findByText("50%")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "CycloneDX SBOM" }));
    await waitFor(() => expect(downloadText).toHaveBeenCalledWith("project-p-1-cyclonedx.json", '{"bomFormat":"CycloneDX"}'));
    expect(getProjectScanSbom).toHaveBeenCalledWith("p-1", "ps-1", "cyclonedx");
  });

  it("reports a missing project instead of an empty page", async () => {
    vi.mocked(getProject).mockRejectedValue(httpError(404, { data: { error: { code: "not_found", message: "Project not found" } } }));
    renderAt("/projects/missing", "admin");
    expect(await screen.findByText("This project could not be loaded")).toBeInTheDocument();
  });
});
