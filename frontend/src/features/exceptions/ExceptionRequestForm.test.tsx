import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../../App";
import { listExceptions, requestException } from "../../api/exceptions";
import { listPolicies } from "../../api/policies";
import type { Policy, PolicyException, Role } from "../../api/types";
import { AuthContext } from "../../auth/context";
import Exceptions from "../../pages/Exceptions";
import { makeAuthState } from "../../test/auth";
import { httpError } from "../../test/http";
import { localDateString, parseLocalDate } from "./validation";

vi.mock("../../api/exceptions", () => ({
  listExceptions: vi.fn(),
  requestException: vi.fn(),
  transitionException: vi.fn(),
}));
vi.mock("../../api/policies", () => ({ listPolicies: vi.fn() }));

const DAY = 86_400_000;
const JUSTIFICATION = "Build step fetches wheels from our internal mirror over HTTPS.";

// Test fixtures: hand-written, not data from a deployment.
const STAGING_POLICY: Policy = {
  id: "p-staging",
  name: "staging-default",
  is_active: true,
  warn_threshold: 40,
  block_threshold: 70,
  min_package_age_days: 0,
  blocked_capabilities: [],
  allowlist: [],
  denylist: [],
  created_at: "2026-09-01T10:00:00Z",
  updated_at: null,
  environment: "staging",
  version: 1,
};

function dateInDays(days: number): string {
  return localDateString(new Date(Date.now() + days * DAY));
}

function created(overrides: Partial<PolicyException> = {}): PolicyException {
  return {
    id: "exc-new",
    policy_id: null,
    package: "internal-mirror-client",
    version_spec: null,
    codes: [],
    categories: [],
    environment: null,
    justification: JUSTIFICATION,
    requested_by: "user-1",
    approved_by: null,
    revoked_by: null,
    status: "pending",
    active: false,
    expires_at: new Date(Date.now() + 30 * DAY).toISOString(),
    created_at: new Date().toISOString(),
    decided_at: null,
    revoked_at: null,
    ...overrides,
  };
}

function renderPage(role: Role, path = "/exceptions") {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter initialEntries={[path]}>
        <Exceptions />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

async function openForm(user: ReturnType<typeof userEvent.setup>): Promise<HTMLElement> {
  await user.click(await screen.findByRole("button", { name: "Request exception" }));
  return screen.getByRole("region", { name: "Request a policy exception" });
}

describe("Exception request form", () => {
  beforeEach(() => {
    vi.mocked(listExceptions).mockReset().mockResolvedValue({ items: [], total: 0, limit: 25, offset: 0 });
    vi.mocked(requestException).mockReset();
    vi.mocked(listPolicies).mockReset().mockResolvedValue([STAGING_POLICY]);
  });

  it("is only offered to roles with exception:request", async () => {
    renderPage("auditor");
    expect(await screen.findByText("No requests are waiting for a decision.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Request exception" })).toBeNull();
  });

  it("lists every problem in a focused summary instead of sending an incomplete request", async () => {
    const user = userEvent.setup();
    renderPage("developer");
    const form = await openForm(user);
    expect(within(form).getByLabelText("Package name")).toHaveFocus();

    await user.click(within(form).getByRole("button", { name: "Send request" }));

    const summary = within(form).getByRole("alert", { name: "Fix 3 problems before sending the request" });
    expect(summary).toHaveFocus();
    expect(requestException).not.toHaveBeenCalled();
    expect(within(form).getByLabelText("Package name")).toHaveAttribute("aria-invalid", "true");
    expect(within(form).getByLabelText("Expiry date")).toHaveAccessibleDescription(/Choose the date the exception expires/);

    await user.click(within(summary).getByRole("button", { name: /Justification: Explain why/ }));
    expect(within(form).getByLabelText("Justification")).toHaveFocus();
  });

  it("checks the package name, specifier and expiry as the server does", async () => {
    const user = userEvent.setup();
    renderPage("developer");
    const form = await openForm(user);

    const name = within(form).getByLabelText("Package name");
    await user.type(name, "evil pkg; rm -rf /");
    await user.tab();
    expect(name).toHaveAttribute("aria-invalid", "true");
    expect(name).toHaveAccessibleDescription(/Enter a valid PyPI package name/);

    await user.clear(name);
    await user.type(name, "Internal_Mirror..Client");
    expect(name).not.toHaveAttribute("aria-invalid");
    expect(within(form).getByText("internal-mirror-client")).toBeInTheDocument();

    const spec = within(form).getByLabelText("Version specifier");
    await user.type(spec, "latest please");
    await user.tab();
    expect(spec).toHaveAccessibleDescription(/Use PEP 440 specifiers/);

    const expiry = within(form).getByLabelText("Expiry date");
    fireEvent.change(expiry, { target: { value: dateInDays(400) } });
    fireEvent.blur(expiry);
    expect(expiry).toHaveAccessibleDescription(/at most 365 days from now/);
    fireEvent.change(expiry, { target: { value: localDateString(new Date()) } });
    expect(expiry).toHaveAccessibleDescription(/must be after today/);
    fireEvent.change(expiry, { target: { value: dateInDays(30) } });
    expect(expiry).not.toHaveAttribute("aria-invalid");
  });

  it("sends a normalised request, then shows it as the requester's pending exception", async () => {
    const user = userEvent.setup();
    vi.mocked(requestException).mockResolvedValue(
      created({ codes: ["NETWORK_EGRESS"], categories: ["capability"], environment: "staging", policy_id: "p-staging" }),
    );
    renderPage("developer", "/exceptions?status=expired");
    const form = await openForm(user);
    const expiresOn = dateInDays(30);

    await user.type(within(form).getByLabelText("Package name"), "Internal_Mirror.Client");
    await user.type(within(form).getByLabelText("Version specifier"), ">=1.4, <2.0");
    await user.selectOptions(within(form).getByLabelText("Policy"), "p-staging");
    const environment = within(form).getByLabelText("Environment");
    expect(environment).toBeDisabled();
    expect(environment).toHaveValue("staging");
    await user.click(within(form).getByRole("checkbox", { name: "Capability" }));
    await user.type(within(form).getByLabelText("Filter finding codes"), "egress");
    await user.click(within(form).getByRole("checkbox", { name: "NETWORK_EGRESS" }));
    expect(within(form).queryByRole("checkbox", { name: "IOC_MATCH" })).toBeNull();
    // Pasted rather than typed: every keystroke re-renders the whole form, which is slow under jsdom.
    await user.click(within(form).getByLabelText("Justification"));
    await user.paste(`  ${JUSTIFICATION}  `);
    fireEvent.change(within(form).getByLabelText("Expiry date"), { target: { value: expiresOn } });
    await user.click(within(form).getByRole("button", { name: "Send request" }));

    expect(requestException).toHaveBeenCalledWith({
      package: "Internal_Mirror.Client",
      version_spec: ">=1.4,<2.0",
      policy_id: "p-staging",
      environment: "staging",
      codes: ["NETWORK_EGRESS"],
      categories: ["capability"],
      justification: JUSTIFICATION,
      expires_at: parseLocalDate(expiresOn)?.toISOString(),
    });
    const notice = await screen.findByText(/Requested an exception for internal-mirror-client/);
    await waitFor(() => expect(notice).toHaveFocus());
    expect(screen.queryByRole("region", { name: "Request a policy exception" })).toBeNull();
    expect(screen.getByRole("tab", { name: "Pending" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("button", { name: "Withdraw request" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  }, 20_000);

  it("keeps what was entered and shows the server's reason when the request is refused", async () => {
    const user = userEvent.setup();
    vi.mocked(requestException).mockRejectedValue(
      httpError(422, {
        data: { error: { code: "validation_error", message: "expires_at: Value error, expires_at must be in the future", request_id: "req-3" } },
      }),
    );
    renderPage("developer");
    const form = await openForm(user);

    await user.type(within(form).getByLabelText("Package name"), "internal-mirror-client");
    await user.click(within(form).getByLabelText("Justification"));
    await user.paste(JUSTIFICATION);
    fireEvent.change(within(form).getByLabelText("Expiry date"), { target: { value: dateInDays(30) } });
    await user.click(within(form).getByRole("button", { name: "Send request" }));

    expect(await within(form).findByText("The exception was not requested")).toBeInTheDocument();
    expect(within(form).getByText(/expires_at must be in the future/)).toBeInTheDocument();
    expect(within(form).getByLabelText("Package name")).toHaveValue("internal-mirror-client");
    expect(within(form).getByRole("button", { name: "Send request" })).toBeEnabled();
  });

  it("returns focus to the request button when the form is cancelled", async () => {
    const user = userEvent.setup();
    renderPage("developer");
    const form = await openForm(user);
    await user.click(within(form).getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Request exception" })).toHaveFocus();
  });
});

describe("Exceptions route", () => {
  beforeEach(() => {
    vi.mocked(listExceptions).mockReset().mockResolvedValue({ items: [], total: 0, limit: 25, offset: 0 });
    vi.mocked(listPolicies).mockReset().mockResolvedValue([]);
  });

  it("replaces the placeholder section with the exceptions workflow", async () => {
    render(
      <AuthContext.Provider value={makeAuthState("auditor")}>
        <MemoryRouter initialEntries={["/exceptions"]}>
          <App />
        </MemoryRouter>
      </AuthContext.Provider>,
    );
    expect(await screen.findByRole("heading", { name: "Policy exceptions", level: 1 })).toBeInTheDocument();
    expect(screen.queryByText("This view is not available yet.")).toBeNull();
  });
});
