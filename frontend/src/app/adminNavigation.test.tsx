import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { getSystemInfo, getSystemTools } from "../api/system";
import type { Role } from "../api/types";
import { listUsers } from "../api/users";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { preloadRoutes } from "../test/preloadRoutes";

vi.mock("../api/users", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/users")>()),
  listUsers: vi.fn(),
}));
vi.mock("../api/system", () => ({ getSystemInfo: vi.fn(), getSystemTools: vi.fn() }));

function renderApp(role: Role, path: string) {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("Users and System navigation", () => {
  beforeAll(preloadRoutes);

  beforeEach(() => {
    vi.mocked(listUsers).mockReset().mockResolvedValue({ items: [], total: 0, limit: 25, offset: 0 });
    vi.mocked(getSystemInfo).mockReset().mockReturnValue(new Promise<never>(() => undefined));
    vi.mocked(getSystemTools).mockReset().mockReturnValue(new Promise<never>(() => undefined));
  });

  it("offers Users and System to an admin under Administration", async () => {
    renderApp("admin", "/users");
    expect(await screen.findByRole("heading", { name: "Users", level: 1 })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("heading", { name: "Administration" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Users" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "System" })).toBeInTheDocument();
    // The page fetches in an effect, so the call can land after its heading renders.
    await waitFor(() => expect(listUsers).toHaveBeenCalledOnce());
  });

  it("offers System but not Users to an auditor, and refuses the Users page", async () => {
    renderApp("auditor", "/users");
    expect(await screen.findByRole("heading", { name: "Access restricted" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Users" })).toBeNull();
    expect(within(nav).getByRole("link", { name: "System" })).toBeInTheDocument();
    expect(listUsers).not.toHaveBeenCalled();
  });

  it("opens the System page, not a placeholder, for an auditor", async () => {
    renderApp("auditor", "/system");
    expect(await screen.findByRole("heading", { name: "System", level: 1 })).toBeInTheDocument();
    expect(screen.queryByText("This view is not available yet.")).toBeNull();
    await waitFor(() => expect(getSystemInfo).toHaveBeenCalledOnce());
  });

  it("hides both from a developer and refuses the System page", async () => {
    renderApp("developer", "/system");
    expect(await screen.findByRole("heading", { name: "Access restricted" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).toBeNull();
    expect(screen.queryByRole("link", { name: "System" })).toBeNull();
    expect(getSystemInfo).not.toHaveBeenCalled();
  });
});
