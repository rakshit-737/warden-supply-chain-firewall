import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getSystemInfo, getSystemTools } from "../api/system";
import type { Role } from "../api/types";
import { AuthContext } from "../auth/context";
import { ALL_TOOLS_AVAILABLE, DEVELOPMENT_INFO, PRODUCTION_INFO, TOOLS } from "../features/system/fixtures";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import SystemPage from "./System";

vi.mock("../api/system", () => ({ getSystemInfo: vi.fn(), getSystemTools: vi.fn() }));

function renderSystem(role: Role) {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter>
        <SystemPage />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

/** The dt/dd pair for `label` inside `container`, as one text string. */
function settingRow(container: HTMLElement, label: string): HTMLElement {
  const term = within(container).getByText(label);
  const row = term.parentElement;
  if (!row) throw new Error(`No row for ${label}`);
  return row;
}

describe("System", () => {
  beforeEach(() => {
    vi.mocked(getSystemInfo).mockReset().mockResolvedValue(DEVELOPMENT_INFO);
    vi.mocked(getSystemTools).mockReset().mockResolvedValue(TOOLS);
  });

  it("does not request system information for a role without system:read", () => {
    renderSystem("developer");
    expect(screen.getByRole("heading", { name: "Access restricted" })).toBeInTheDocument();
    expect(getSystemInfo).not.toHaveBeenCalled();
    expect(getSystemTools).not.toHaveBeenCalled();
  });

  it("shows grouped settings, tool availability and posture observations to an auditor", async () => {
    renderSystem("auditor");

    const posture = await screen.findByRole("region", { name: "Security posture" });
    expect(within(posture).getByText("Metrics can be read without a token")).toBeInTheDocument();
    expect(within(posture).getByText("Caching and rate limiting are in-process")).toBeInTheDocument();
    expect(within(posture).getByText('The environment is "development", not production')).toBeInTheDocument();
    expect(await within(posture).findByText("semgrep is enabled but not available")).toBeInTheDocument();

    const deployment = screen.getByRole("region", { name: "Deployment" });
    expect(settingRow(deployment, "Server version")).toHaveTextContent("Server version2.1.0");
    expect(settingRow(deployment, "Environment")).toHaveTextContent("EnvironmentDevelopment");
    expect(settingRow(screen.getByRole("region", { name: "Runtime" }), "Trusted proxies configured")).toHaveTextContent(
      "Trusted proxies configuredNo",
    );

    const intel = within(screen.getByRole("region", { name: "Features" })).getByRole("region", {
      name: "Vulnerability intelligence",
    });
    expect(settingRow(intel, "Intelligence lookups")).toHaveTextContent("Intelligence lookupsOn");
    expect(settingRow(intel, "NVD source")).toHaveTextContent("NVD sourceOff");

    const limits = screen.getByRole("region", { name: "Limits" });
    expect(settingRow(limits, "Request body")).toHaveTextContent("Request body4 MiB");
    expect(settingRow(limits, "Scan timeout")).toHaveTextContent("Scan timeout3 minutes");
    expect(settingRow(limits, "API rate limit")).toHaveTextContent("API rate limit120 per minute");
    expect(screen.queryByRole("region", { name: "Other reported values" })).toBeNull();

    const tools = screen.getByRole("region", { name: "Analysis tools" });
    expect(within(within(tools).getByRole("row", { name: /semgrep/ })).getByText("Not available")).toBeInTheDocument();
    expect(within(within(tools).getByRole("row", { name: /syft/ })).getByText("1.18.1")).toBeInTheDocument();
  });

  it("renders reported text as text, never as markup", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    vi.mocked(getSystemInfo).mockResolvedValue({ ...PRODUCTION_INFO, version: hostile, analyzer_version: `${hostile}‮` });
    vi.mocked(getSystemTools).mockResolvedValue([{ name: "semgrep", available: true, version: hostile, detail: hostile }]);
    renderSystem("admin");

    // The loading placeholder is also titled Deployment, so look the card up once the data has rendered.
    await screen.findByRole("region", { name: "Security posture" });
    const deployment = screen.getByRole("region", { name: "Deployment" });
    expect(settingRow(deployment, "Server version")).toHaveTextContent(hostile);
    expect(settingRow(deployment, "Analyzer version")).toHaveTextContent(`${hostile}<U+202E>`);
    expect(await screen.findAllByText(hostile)).toHaveLength(3);
    expect(document.querySelector("img")).toBeNull();
  });

  it("keeps system information on screen when the tool list fails, and retries it", async () => {
    const user = userEvent.setup();
    vi.mocked(getSystemTools).mockRejectedValueOnce(httpError(503)).mockResolvedValue(TOOLS);
    renderSystem("admin");

    const tools = screen.getByRole("region", { name: "Analysis tools" });
    const alert = await within(tools).findByRole("alert");
    expect(alert).toHaveTextContent("The Warden API is temporarily unavailable.");
    const posture = await screen.findByRole("region", { name: "Security posture" });
    expect(posture).toHaveTextContent("Not assessed, because the server did not report it or it has not loaded: analysis tools.");

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await within(tools).findByRole("row", { name: /semgrep/ })).toBeInTheDocument();
    expect(getSystemTools).toHaveBeenCalledTimes(2);
    expect(getSystemInfo).toHaveBeenCalledOnce();
  });

  it("offers a retry when system information cannot be loaded", async () => {
    const user = userEvent.setup();
    vi.mocked(getSystemInfo)
      .mockRejectedValueOnce(httpError(502))
      .mockResolvedValue(PRODUCTION_INFO);
    vi.mocked(getSystemTools).mockResolvedValue(ALL_TOOLS_AVAILABLE);
    renderSystem("auditor");

    const title = await screen.findByText("System information could not be loaded");
    const alert = title.closest<HTMLElement>('[role="alert"]');
    if (!alert) throw new Error("The error is not announced");
    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    const posture = await screen.findByRole("region", { name: "Security posture" });
    expect(await within(posture).findByText("Nothing stood out in the reported settings.")).toBeInTheDocument();
  });
});
