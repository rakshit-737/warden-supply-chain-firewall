import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { activatePolicy, listPolicies, updatePolicy } from "../api/policies";
import type { Policy, Role } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import Policies from "./Policies";

vi.mock("../api/policies", () => ({
  listPolicies: vi.fn(),
  createPolicy: vi.fn(),
  updatePolicy: vi.fn(),
  activatePolicy: vi.fn(),
}));

// Test fixtures: hand-written policies, not data from a deployment.
const PRODUCTION: Policy = {
  id: "p-production",
  name: "prod-default",
  is_active: true,
  warn_threshold: 40,
  block_threshold: 70,
  min_package_age_days: 0,
  blocked_capabilities: [],
  allowlist: [],
  denylist: [],
  created_at: "2026-09-01T10:00:00Z",
  updated_at: null,
  environment: "production",
  version: 1,
};
const STRICT: Policy = { ...PRODUCTION, id: "p-strict", name: "prod-strict", is_active: false, warn_threshold: 30, block_threshold: 60 };

function renderPolicies(role: Role) {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter>
        <Policies />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("Policies", () => {
  beforeEach(() => {
    vi.mocked(listPolicies).mockReset().mockResolvedValue([PRODUCTION, STRICT]);
    vi.mocked(updatePolicy).mockReset();
    vi.mocked(activatePolicy).mockReset();
  });

  it("lets a read-only user review policies without any way to change them", async () => {
    renderPolicies("read_only");
    expect(await screen.findByRole("button", { name: "prod-strict" })).toBeInTheDocument();
    expect(screen.getByText("You can review policies. Changing them requires the admin role.")).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Policy settings" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Activate" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Save changes|Create policy/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "New policy" })).toBeNull();
  });

  it("lets an admin save changes to the selected policy", async () => {
    const user = userEvent.setup();
    vi.mocked(updatePolicy).mockResolvedValue({ ...PRODUCTION, warn_threshold: 45, version: 2 });
    renderPolicies("admin");

    const warn = await screen.findByLabelText("Warn at risk score");
    await user.clear(warn);
    await user.type(warn, "45");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    expect(updatePolicy).toHaveBeenCalledWith(
      "p-production",
      expect.objectContaining({ name: "prod-default", warn_threshold: 45, block_threshold: 70 }),
    );
    expect(await screen.findByText("Saved prod-default.")).toBeInTheDocument();
  });

  it("moves focus to the confirmation after activating, although the Activate button then disappears", async () => {
    const user = userEvent.setup();
    const activated: Policy = { ...STRICT, is_active: true };
    vi.mocked(activatePolicy).mockResolvedValue(activated);
    vi.mocked(listPolicies)
      .mockResolvedValueOnce([PRODUCTION, STRICT])
      .mockResolvedValue([activated, { ...PRODUCTION, is_active: false }]);
    renderPolicies("admin");

    await user.click(await screen.findByRole("button", { name: "Activate" }));
    const dialog = screen.getByRole("alertdialog", { name: "Activate prod-strict?" });
    await user.click(within(dialog).getByRole("button", { name: "Activate policy" }));

    const notice = await screen.findByText("prod-strict is now the active production policy.");
    expect(notice).toHaveFocus();
    await waitFor(() => {
      const row = screen.getByRole("row", { name: /prod-strict/ });
      expect(within(row).queryByRole("button", { name: "Activate" })).toBeNull();
    });
    expect(notice).toHaveFocus();
  });

  it("keeps the dialog open with the server's reason when activation fails", async () => {
    const user = userEvent.setup();
    vi.mocked(activatePolicy).mockRejectedValue(
      httpError(409, { data: { error: { code: "conflict", message: "Another policy was activated meanwhile.", request_id: "req-9" } } }),
    );
    renderPolicies("admin");

    await user.click(await screen.findByRole("button", { name: "Activate" }));
    const dialog = screen.getByRole("alertdialog", { name: "Activate prod-strict?" });
    await user.click(within(dialog).getByRole("button", { name: "Activate policy" }));

    expect(await within(dialog).findByText("The policy was not activated")).toBeInTheDocument();
    expect(within(dialog).getByText("Another policy was activated meanwhile.")).toBeInTheDocument();
    expect(screen.queryByText(/is now the active/)).toBeNull();
  });
});
