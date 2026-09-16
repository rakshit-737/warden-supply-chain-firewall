import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listExceptions, requestException, transitionException } from "../api/exceptions";
import { listPolicies } from "../api/policies";
import type { Page, PolicyException, Role } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import Exceptions from "./Exceptions";

vi.mock("../api/exceptions", () => ({
  listExceptions: vi.fn(),
  requestException: vi.fn(),
  transitionException: vi.fn(),
}));
vi.mock("../api/policies", () => ({ listPolicies: vi.fn() }));

const DAY = 86_400_000;

function fromNow(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

// Test fixtures: hand-written exceptions, not data from a deployment. makeAuthState signs in "user-1".
function makeException(overrides: Partial<PolicyException> = {}): PolicyException {
  return {
    id: "exc-1",
    policy_id: null,
    package: "internal-mirror-client",
    version_spec: "<2.0",
    codes: ["NETWORK_EGRESS"],
    categories: ["capability"],
    environment: "production",
    justification: "Build step fetches wheels from our internal mirror over HTTPS.",
    requested_by: "user-2",
    approved_by: null,
    revoked_by: null,
    status: "pending",
    active: false,
    // A minute of slack so the countdown still reads "10 days" when the test renders.
    expires_at: fromNow(10 * DAY + 60_000),
    created_at: fromNow(-DAY),
    decided_at: null,
    revoked_at: null,
    ...overrides,
  };
}

function pageOf(items: PolicyException[]): Page<PolicyException> {
  return { items, total: items.length, limit: 25, offset: 0 };
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

async function openDetails(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: /internal-mirror-client/ }));
}

describe("Exceptions page", () => {
  beforeEach(() => {
    vi.mocked(listExceptions).mockReset().mockResolvedValue(pageOf([makeException()]));
    vi.mocked(requestException).mockReset();
    vi.mocked(transitionException).mockReset();
    vi.mocked(listPolicies).mockReset().mockResolvedValue([]);
  });

  it("lists pending requests with an expiry countdown and loads the status tab the user picks", async () => {
    const user = userEvent.setup();
    renderPage("read_only");

    const row = await screen.findByRole("row", { name: /internal-mirror-client/ });
    expect(within(row).getByText("Expires in 10 days")).toBeInTheDocument();
    expect(within(row).getByText("Pending")).toBeInTheDocument();
    expect(listExceptions).toHaveBeenCalledWith(
      expect.objectContaining({ status: "pending", limit: 25, offset: 0 }),
      expect.anything(),
    );

    await user.click(screen.getByRole("tab", { name: "Approved (active)" }));
    await waitFor(() =>
      expect(listExceptions).toHaveBeenLastCalledWith(expect.objectContaining({ status: "approved" }), expect.anything()),
    );
    await user.click(screen.getByRole("tab", { name: "All" }));
    await waitFor(() =>
      expect(listExceptions).toHaveBeenLastCalledWith(expect.objectContaining({ status: undefined }), expect.anything()),
    );
  });

  it("opens the approved tab for the active status", async () => {
    renderPage("read_only", "/exceptions?status=active");
    expect(await screen.findByRole("tab", { name: "Approved (active)" })).toHaveAttribute("aria-selected", "true");
    expect(listExceptions).toHaveBeenCalledWith(expect.objectContaining({ status: "approved" }), expect.anything());
  });

  it("gives a read-only user no way to request or decide exceptions", async () => {
    const user = userEvent.setup();
    renderPage("read_only");
    await openDetails(user);

    expect(screen.getByText(/Your role can review exceptions/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Request exception" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Revoke|Withdraw/ })).toBeNull();
    expect(screen.getByText(/Waiting for a decision by someone with the exception:approve permission/)).toBeInTheDocument();
    expect(screen.getByText("Build step fetches wheels from our internal mirror over HTTPS.")).toBeInTheDocument();
  });

  it("does not let an approver decide their own request (separation of duties)", async () => {
    const user = userEvent.setup();
    vi.mocked(listExceptions).mockResolvedValue(pageOf([makeException({ requested_by: "user-1" })]));
    renderPage("security_analyst");
    await openDetails(user);

    const approve = screen.getByRole("button", { name: "Approve" });
    const reject = screen.getByRole("button", { name: "Reject" });
    expect(approve).toHaveAttribute("aria-disabled", "true");
    expect(reject).toHaveAttribute("aria-disabled", "true");
    expect(approve).toHaveAccessibleDescription(/Separation of duties requires a different approver/);
    await user.click(approve);
    await user.click(reject);
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getByRole("button", { name: "Withdraw request" })).not.toHaveAttribute("aria-disabled");
  });

  it("approves someone else's request only with a comment, then confirms and moves focus", async () => {
    const user = userEvent.setup();
    const pending = makeException();
    vi.mocked(listExceptions).mockResolvedValueOnce(pageOf([pending])).mockResolvedValue(pageOf([]));
    vi.mocked(transitionException).mockResolvedValue({
      ...pending,
      status: "approved",
      active: true,
      approved_by: "user-1",
      decided_at: fromNow(0),
    });
    renderPage("security_analyst");
    await openDetails(user);

    await user.click(screen.getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("alertdialog", { name: "Approve the exception for internal-mirror-client?" });
    expect(within(dialog).getByText(pending.justification)).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Approve exception" }));
    const comment = within(dialog).getByLabelText("Comment");
    expect(comment).toHaveFocus();
    expect(comment).toHaveAttribute("aria-invalid", "true");
    expect(comment).toHaveAccessibleDescription(/Enter a comment/);
    expect(transitionException).not.toHaveBeenCalled();

    await user.type(comment, "Reviewed with the platform team");
    await user.click(within(dialog).getByRole("button", { name: "Approve exception" }));

    expect(transitionException).toHaveBeenCalledWith("exc-1", "approve", "Reviewed with the platform team");
    const notice = await screen.findByText(
      "Approved the exception for internal-mirror-client. It applies until it expires or is revoked.",
    );
    await waitFor(() => expect(notice).toHaveFocus());
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    await waitFor(() => expect(listExceptions).toHaveBeenCalledTimes(2));
  });

  it("explains a separation-of-duties refusal from the server inside the dialog", async () => {
    const user = userEvent.setup();
    vi.mocked(transitionException).mockRejectedValue(
      httpError(403, {
        data: {
          error: {
            code: "separation_of_duties",
            message: "Separation of duties: the requester of an exception cannot approve or reject it",
            request_id: "req-7",
          },
        },
      }),
    );
    renderPage("admin");
    await openDetails(user);

    await user.click(screen.getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("alertdialog");
    await user.type(within(dialog).getByLabelText("Comment"), "Looks fine");
    await user.click(within(dialog).getByRole("button", { name: "Approve exception" }));

    expect(
      await within(dialog).findByText("Separation of duties: a different approver must decide this request"),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(/cannot approve or reject it/)).toBeInTheDocument();
    expect(within(dialog).getByText("req-7")).toBeInTheDocument();
    expect(screen.queryByText(/^Approved the exception/)).toBeNull();
  });

  it("refreshes the list when the exception changed before the decision was saved", async () => {
    const user = userEvent.setup();
    vi.mocked(transitionException).mockRejectedValue(
      httpError(409, {
        data: {
          error: {
            code: "conflict",
            message: "Only pending exceptions can be decided (current status: approved)",
            request_id: "req-8",
          },
        },
      }),
    );
    renderPage("security_analyst");
    await openDetails(user);

    await user.click(screen.getByRole("button", { name: "Reject" }));
    const dialog = screen.getByRole("alertdialog", { name: "Reject the exception request for internal-mirror-client?" });
    await user.type(within(dialog).getByLabelText("Comment"), "Scope is too broad");
    await user.click(within(dialog).getByRole("button", { name: "Reject request" }));

    expect(await within(dialog).findByText("The exception changed before this was saved")).toBeInTheDocument();
    expect(within(dialog).getByText(/The list has been refreshed/)).toBeInTheDocument();
    expect(transitionException).toHaveBeenCalledWith("exc-1", "reject", "Scope is too broad");
    await waitFor(() => expect(listExceptions).toHaveBeenCalledTimes(2));
  });

  it("shows an approved exception past its expiry as expired, with no actions", async () => {
    const user = userEvent.setup();
    vi.mocked(listExceptions).mockResolvedValue(
      pageOf([
        makeException({
          status: "approved",
          active: true,
          approved_by: "user-3",
          decided_at: fromNow(-5 * DAY),
          expires_at: fromNow(-2 * DAY - 60_000),
        }),
      ]),
    );
    renderPage("security_analyst", "/exceptions?status=all");

    const row = await screen.findByRole("row", { name: /internal-mirror-client/ });
    expect(within(row).getByText("Expired")).toBeInTheDocument();
    expect(within(row).getByText("Expired 2 days ago")).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: /internal-mirror-client/ }));

    expect(screen.getByText(/This exception has expired/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("shows the empty state of the tab", async () => {
    vi.mocked(listExceptions).mockResolvedValue(pageOf([]));
    renderPage("developer");
    expect(await screen.findByText("No requests are waiting for a decision.")).toBeInTheDocument();
  });

  it("reports a failed load and retries", async () => {
    const user = userEvent.setup();
    vi.mocked(listExceptions).mockReset().mockRejectedValueOnce(httpError(503)).mockResolvedValue(pageOf([makeException()]));
    renderPage("developer");

    expect(await screen.findByText("This data could not be loaded")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("button", { name: /internal-mirror-client/ })).toBeInTheDocument();
  });

  it("does not send a package filter the server would reject", async () => {
    const user = userEvent.setup();
    renderPage("read_only");
    await screen.findByRole("button", { name: /internal-mirror-client/ });

    const filter = screen.getByLabelText("Package (exact name)");
    await user.type(filter, "bad name!");
    expect(filter).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText(/Enter a complete, valid package name/)).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 450));
    expect(listExceptions).toHaveBeenCalledTimes(1);

    await user.clear(filter);
    await user.type(filter, "Internal_Mirror.Client");
    await waitFor(() =>
      expect(listExceptions).toHaveBeenLastCalledWith(
        expect.objectContaining({ package: "Internal_Mirror.Client", status: "pending", offset: 0 }),
        expect.anything(),
      ),
    );
  });
});
