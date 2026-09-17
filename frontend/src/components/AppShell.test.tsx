import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";
import type { Role } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { AppShell } from "./AppShell";

function BrokenView(): never {
  throw new Error("view crashed");
}

function renderShell(role: Role, path = "/scans", page: ReactNode = <p>Page body</p>) {
  const auth = makeAuthState(role);
  render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="*" element={page} />
          </Route>
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
  return auth;
}

describe("AppShell", () => {
  it("groups navigation into sections and marks the current page", () => {
    renderShell("admin");
    for (const heading of ["Overview", "Supply chain", "Operations", "Governance"]) {
      expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
    }
    for (const link of ["Dashboard", "Packages", "Projects", "Release diffs", "Containers", "Events", "Monitoring", "Policies", "Exceptions", "Audit", "System"]) {
      expect(screen.getByRole("link", { name: link })).toBeInTheDocument();
    }
    expect(screen.getByRole("link", { name: "Scans" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("Page body")).toBeInTheDocument();
  });

  it("hides Audit and System from a developer", () => {
    renderShell("developer");
    expect(screen.queryByRole("link", { name: "Audit" })).toBeNull();
    expect(screen.queryByRole("link", { name: "System" })).toBeNull();
    expect(screen.getByText("Developer")).toBeInTheDocument();
  });

  it("shows Audit and System to an auditor", () => {
    renderShell("auditor");
    expect(screen.getByRole("link", { name: "Audit" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "System" })).toBeInTheDocument();
  });

  it("signs out through the auth context", async () => {
    const user = userEvent.setup();
    const auth = renderShell("read_only");
    await user.click(screen.getByRole("button", { name: "Sign out" }));
    expect(auth.logout).toHaveBeenCalledOnce();
  });

  it("makes the page inert while the small-screen menu is open, and closes it with Escape", async () => {
    const user = userEvent.setup();
    renderShell("developer");
    const main = document.getElementById("main-content");

    await user.click(screen.getByRole("button", { name: "Menu" }));
    expect(main).toHaveAttribute("inert");
    expect(screen.getByRole("link", { name: "Dashboard" })).toHaveFocus();

    await user.keyboard("{Escape}");
    const toggle = screen.getByRole("button", { name: "Menu" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(main).not.toHaveAttribute("inert");
    expect(toggle).toHaveFocus();
  });

  it("moves focus to the page after a destination is chosen from the menu", async () => {
    const user = userEvent.setup();
    renderShell("developer", "/");
    await user.click(screen.getByRole("button", { name: "Menu" }));
    await user.click(screen.getByRole("link", { name: "Policies" }));

    const main = document.getElementById("main-content");
    expect(screen.getByRole("button", { name: "Menu" })).toHaveAttribute("aria-expanded", "false");
    expect(main).not.toHaveAttribute("inert");
    expect(main).toHaveFocus();
  });

  it("keeps navigation and sign-out available when the current view fails to render", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    renderShell("admin", "/policies", <BrokenView />);
    expect(screen.getByRole("alert")).toHaveTextContent("This view failed to display");
    expect(screen.getByRole("link", { name: "Scans" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });
});
