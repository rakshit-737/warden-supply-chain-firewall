import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ListUsersParams, Page, Role, User } from "../api/types";
import { listUsers, registerUser, updateUser } from "../api/users";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import UsersPage from "./Users";

vi.mock("../api/users", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/users")>()),
  listUsers: vi.fn(),
  updateUser: vi.fn(),
  registerUser: vi.fn(),
}));

// Test fixtures: hand-written accounts, not data from a deployment. "user-1" is the signed-in user
// that makeAuthState creates.
const ME: User = { id: "user-1", email: "analyst@example.test", role: "admin", is_active: true, created_at: "2026-01-01T00:00:00Z" };
const DEV: User = { id: "u-dev", email: "dev@example.test", role: "developer", is_active: true, created_at: "2026-02-01T00:00:00Z" };
const LEGACY: User = { id: "u-legacy", email: "old@example.test", role: "analyst", is_active: false, created_at: "2025-06-01T00:00:00Z" };

function pageOf(items: User[], params: ListUsersParams = {}): Page<User> {
  return { items, total: items.length, limit: params.limit ?? 25, offset: params.offset ?? 0 };
}

function renderUsers(role: Role = "admin") {
  const auth = makeAuthState(role);
  render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={["/users"]}>
        <UsersPage />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
  return auth;
}

async function openRegistration(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText("analyst@example.test");
  await user.click(screen.getByRole("button", { name: "Register user" }));
  return screen.getByRole("region", { name: "Register a user" });
}

describe("Users", () => {
  beforeEach(() => {
    vi.mocked(listUsers).mockReset().mockResolvedValue(pageOf([ME, DEV]));
    vi.mocked(updateUser).mockReset();
    vi.mocked(registerUser).mockReset();
  });

  it("does not list users for a role without user:manage", () => {
    renderUsers("auditor");
    expect(screen.getByRole("heading", { name: "Access restricted" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register user" })).toBeNull();
    expect(listUsers).not.toHaveBeenCalled();
  });

  it("maps v1 role names for display and never shows password hashes or tokens", async () => {
    const leaky = { ...DEV, password_hash: "$argon2id$v=19$m=65536$c2VjcmV0", access_token: "eyJhbGciOiJIUzI1NiJ9.leak" } as User;
    vi.mocked(listUsers).mockResolvedValue(pageOf([ME, leaky, LEGACY]));
    renderUsers();

    const legacyRow = await screen.findByRole("row", { name: /old@example\.test/ });
    expect(within(legacyRow).getByText("Security analyst")).toBeInTheDocument();
    expect(within(legacyRow).getByText("analyst")).toBeInTheDocument();
    expect(within(legacyRow).getByText("Inactive")).toBeInTheDocument();
    expect(within(legacyRow).getByRole("button", { name: "Reactivate old@example.test" })).toBeInTheDocument();
    expect(within(screen.getByRole("row", { name: /analyst@example\.test/ })).getByText("You")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/argon2|eyJhbGciOi/);
  });

  it("filters by role, status and email on the server", async () => {
    const user = userEvent.setup();
    vi.mocked(listUsers).mockImplementation((params = {}) => Promise.resolve(pageOf([DEV], params)));
    renderUsers();
    await screen.findByText("dev@example.test");

    await user.selectOptions(screen.getByLabelText("Role"), "auditor");
    await user.selectOptions(screen.getByLabelText("Status"), "inactive");
    await user.type(screen.getByLabelText("Email contains"), "dev");

    await waitFor(() =>
      expect(listUsers).toHaveBeenLastCalledWith(
        { limit: 25, offset: 0, q: "dev", role: "auditor", is_active: false },
        expect.anything(),
      ),
    );
  });

  it("pages through users with the server's pagination", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 30 }, (_, index) => ({ ...DEV, id: `u-${index}`, email: `user${index}@example.test` }));
    vi.mocked(listUsers).mockImplementation(({ limit = 25, offset = 0 } = {}) =>
      Promise.resolve({ items: many.slice(offset, offset + limit), total: many.length, limit, offset }),
    );
    renderUsers();

    await screen.findByText("user0@example.test");
    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(await screen.findByText("user25@example.test")).toBeInTheDocument();
    expect(listUsers).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 25 }), expect.anything());
  });

  it("changes a role after confirmation and moves focus to the confirmation", async () => {
    const user = userEvent.setup();
    vi.mocked(updateUser).mockResolvedValue({ ...DEV, role: "security_analyst" });
    const auth = renderUsers();

    await user.click(await screen.findByRole("button", { name: "Change role for dev@example.test" }));
    const dialog = screen.getByRole("alertdialog", { name: "Change role for dev@example.test" });
    const select = within(dialog).getByLabelText("New role");
    await user.selectOptions(select, "security_analyst");
    expect(select).toHaveAccessibleDescription(/^Security analyst: Runs scans, approves exceptions/);
    await user.click(within(dialog).getByRole("button", { name: "Change role" }));

    expect(updateUser).toHaveBeenCalledWith("u-dev", { role: "security_analyst" });
    const notice = await screen.findByText("dev@example.test now has the Security analyst role.");
    expect(notice).toHaveFocus();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await waitFor(() => expect(listUsers).toHaveBeenCalledTimes(2));
    expect(auth.retryRestore).not.toHaveBeenCalled();
  });

  it("does not send a role change that changes nothing", async () => {
    const user = userEvent.setup();
    renderUsers();

    await user.click(await screen.findByRole("button", { name: "Change role for dev@example.test" }));
    const dialog = screen.getByRole("alertdialog", { name: "Change role for dev@example.test" });
    await user.click(within(dialog).getByRole("button", { name: "Change role" }));

    expect(within(dialog).getByRole("alert")).toHaveTextContent("This user already has that role.");
    expect(updateUser).not.toHaveBeenCalled();
  });

  it("keeps the dialog open and explains the server's last-admin protection", async () => {
    const user = userEvent.setup();
    vi.mocked(updateUser).mockRejectedValue(
      httpError(409, {
        data: { error: { code: "last_admin", message: "Refusing to remove the last active admin", request_id: "req-7" } },
      }),
    );
    const auth = renderUsers();

    await user.click(await screen.findByRole("button", { name: "Deactivate analyst@example.test" }));
    const dialog = screen.getByRole("alertdialog", { name: "Deactivate analyst@example.test?" });
    expect(within(dialog).getByText("This is your own account. You will be signed out.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Deactivate user" }));

    expect(updateUser).toHaveBeenCalledWith("user-1", { is_active: false });
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("At least one active admin must remain");
    expect(alert).toHaveTextContent(
      "Refusing to remove the last active admin. Make another user an active admin first, then try again.",
    );
    expect(alert).toHaveTextContent("req-7");
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
    expect(screen.queryByText(/^Deactivated/)).toBeNull();
    expect(auth.retryRestore).not.toHaveBeenCalled();
  });

  it("checks the session again after the signed-in admin changes their own role", async () => {
    const user = userEvent.setup();
    vi.mocked(updateUser).mockResolvedValue({ ...ME, role: "auditor" });
    const auth = renderUsers();

    await user.click(await screen.findByRole("button", { name: "Change role for analyst@example.test" }));
    const dialog = screen.getByRole("alertdialog", { name: "Change role for analyst@example.test" });
    await user.selectOptions(within(dialog).getByLabelText("New role"), "auditor");
    expect(within(dialog).getByText(/This is your own account\. Without the admin role/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Change role" }));

    expect(updateUser).toHaveBeenCalledWith("user-1", { role: "auditor" });
    await waitFor(() => expect(auth.retryRestore).toHaveBeenCalledOnce());
  });

  it("validates the registration form before sending anything", async () => {
    const user = userEvent.setup();
    renderUsers();
    const form = await openRegistration(user);

    const email = within(form).getByLabelText("Email");
    expect(email).toHaveFocus();
    await user.type(email, "new@example.test");
    await user.type(within(form).getByLabelText("Password"), "too-short");
    await user.type(within(form).getByLabelText("Confirm password"), "too-short");
    await user.click(within(form).getByRole("button", { name: "Register user" }));

    expect(within(form).getByRole("alert")).toHaveTextContent("Fix 1 problem to register this user.");
    const password = within(form).getByLabelText("Password");
    expect(password).toHaveFocus();
    expect(password).toHaveAttribute("aria-invalid", "true");
    expect(password).toHaveAccessibleDescription(/^The password must be at least 12 characters\./);
    expect(registerUser).not.toHaveBeenCalled();
  });

  it("registers a user, confirms it and forgets the password", async () => {
    const user = userEvent.setup();
    vi.mocked(listUsers).mockResolvedValue(pageOf([ME]));
    vi.mocked(registerUser).mockResolvedValue({
      id: "u-new",
      email: "new@example.test",
      role: "developer",
      is_active: true,
      created_at: "2026-09-15T12:00:00Z",
    });
    renderUsers();
    const form = await openRegistration(user);

    await user.type(within(form).getByLabelText("Email"), "New@Example.test");
    await user.selectOptions(within(form).getByLabelText("Role"), "developer");
    await user.type(within(form).getByLabelText("Password"), "a sufficiently long passphrase");
    await user.type(within(form).getByLabelText("Confirm password"), "a sufficiently long passphrase");
    await user.click(within(form).getByRole("button", { name: "Register user" }));

    expect(registerUser).toHaveBeenCalledWith({
      email: "New@Example.test",
      password: "a sufficiently long passphrase",
      role: "developer",
    });
    const notice = await screen.findByText("Registered new@example.test with the Developer role.");
    expect(notice).toHaveFocus();
    expect(screen.queryByRole("region", { name: "Register a user" })).toBeNull();
    expect(document.querySelector('input[type="password"]')).toBeNull();
    await waitFor(() => expect(listUsers).toHaveBeenCalledTimes(2));
  });

  it("shows a taken email next to the email field", async () => {
    const user = userEvent.setup();
    vi.mocked(registerUser).mockRejectedValue(
      httpError(409, { data: { error: { code: "conflict", message: "A user with that email already exists", request_id: "req-3" } } }),
    );
    renderUsers();
    const form = await openRegistration(user);

    await user.type(within(form).getByLabelText("Email"), "dev@example.test");
    await user.type(within(form).getByLabelText("Password"), "a sufficiently long passphrase");
    await user.type(within(form).getByLabelText("Confirm password"), "a sufficiently long passphrase");
    await user.click(within(form).getByRole("button", { name: "Register user" }));

    const email = within(form).getByLabelText("Email");
    await waitFor(() => expect(email).toHaveFocus());
    expect(email).toHaveAttribute("aria-invalid", "true");
    expect(email).toHaveAccessibleDescription("A user with that email already exists.");
    expect(screen.getByRole("region", { name: "Register a user" })).toBeInTheDocument();
  });

  it("returns focus to Register user when registration is cancelled", async () => {
    const user = userEvent.setup();
    renderUsers();
    const form = await openRegistration(user);

    await user.click(within(form).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("region", { name: "Register a user" })).toBeNull();
    const toggle = screen.getByRole("button", { name: "Register user" });
    expect(toggle).toHaveFocus();
    expect(toggle).toHaveAttribute("aria-expanded", "false");
  });

  it("offers a retry when the user list cannot be loaded", async () => {
    const user = userEvent.setup();
    vi.mocked(listUsers).mockRejectedValueOnce(httpError(503)).mockResolvedValue(pageOf([DEV]));
    renderUsers();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("This data could not be loaded");
    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("dev@example.test")).toBeInTheDocument();
  });
});
