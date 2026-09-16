import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeAll, describe, expect, it } from "vitest";
import App from "./App";
import { AuthContext, type AuthState } from "./auth/context";
import { makeAuthState } from "./test/auth";
import { preloadRoutes } from "./test/preloadRoutes";

function renderApp(auth: AuthState, path: string) {
  render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("App", () => {
  beforeAll(preloadRoutes);

  it("does not open the audit section for a role without audit:read", async () => {
    renderApp(makeAuthState("developer"), "/audit");
    expect(await screen.findByRole("heading", { name: "Access restricted" })).toBeInTheDocument();
    expect(screen.queryByText(/append-only audit trail/)).toBeNull();
  });

  it("opens the audit section for an auditor", async () => {
    renderApp(makeAuthState("auditor"), "/audit");
    expect(await screen.findByRole("heading", { name: "Audit", level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/append-only audit trail/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Access restricted" })).toBeNull();
  });

  it("offers to check the session again, not the sign-in form, when the session check failed", async () => {
    const user = userEvent.setup();
    const auth = makeAuthState(null, {
      restoreError: {
        status: 429,
        code: null,
        message: "Too many requests. Wait a moment and try again.",
        requestId: null,
        retryAfterSeconds: 30,
      },
    });
    renderApp(auth, "/");

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Your session could not be checked");
    expect(alert).toHaveTextContent("about 30 seconds");
    expect(screen.queryByLabelText("Password")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(auth.retryRestore).toHaveBeenCalledOnce();
  });

  it("shows the sign-in form when there is no session", async () => {
    renderApp(makeAuthState(null), "/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});
