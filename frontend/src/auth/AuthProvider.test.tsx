import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { me } from "../api/auth";
import { refreshSession } from "../api/client";
import { makeUser } from "../test/auth";
import { httpError, noResponseError } from "../test/http";
import { AuthProvider } from "./AuthProvider";
import { useAuth } from "./useAuth";

vi.mock("../api/auth", () => ({ login: vi.fn(), logout: vi.fn(), me: vi.fn() }));
vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, refreshSession: vi.fn() };
});

function SessionProbe() {
  const { user, loading, restoreError, retryRestore } = useAuth();
  if (loading) return <p>Checking session</p>;
  if (restoreError) {
    return (
      <div>
        <p>Session check failed: {restoreError.message}</p>
        <button type="button" onClick={retryRestore}>
          Check again
        </button>
      </div>
    );
  }
  return <p>{user ? `Signed in as ${user.email}` : "Signed out"}</p>;
}

function renderProvider() {
  render(
    <AuthProvider>
      <SessionProbe />
    </AuthProvider>,
  );
}

describe("AuthProvider session restore", () => {
  beforeEach(() => {
    vi.mocked(refreshSession).mockReset();
    vi.mocked(me).mockReset();
  });

  it("restores the session through the refresh cookie", async () => {
    vi.mocked(refreshSession).mockResolvedValue("token-1");
    vi.mocked(me).mockResolvedValue(makeUser("developer"));
    renderProvider();
    expect(await screen.findByText("Signed in as analyst@example.test")).toBeInTheDocument();
  });

  it("is signed out when the server refuses the session", async () => {
    vi.mocked(refreshSession).mockResolvedValue(null);
    renderProvider();
    expect(await screen.findByText("Signed out")).toBeInTheDocument();
    expect(me).not.toHaveBeenCalled();
  });

  it("does not sign the user out when the check is rate limited, and checks again on request", async () => {
    const user = userEvent.setup();
    vi.mocked(refreshSession)
      .mockRejectedValueOnce(httpError(429, { headers: { "retry-after": "20" } }))
      .mockResolvedValueOnce("token-2");
    vi.mocked(me).mockResolvedValue(makeUser("admin"));
    renderProvider();

    expect(await screen.findByText(/Session check failed: Too many requests/)).toBeInTheDocument();
    expect(screen.queryByText("Signed out")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Check again" }));
    expect(await screen.findByText("Signed in as analyst@example.test")).toBeInTheDocument();
  });

  it("is signed out when /auth/me refuses the new token", async () => {
    vi.mocked(refreshSession).mockResolvedValue("token-3");
    vi.mocked(me).mockRejectedValue(httpError(401));
    renderProvider();
    expect(await screen.findByText("Signed out")).toBeInTheDocument();
  });

  it("reports a failed check when /auth/me cannot be reached", async () => {
    vi.mocked(refreshSession).mockResolvedValue("token-4");
    vi.mocked(me).mockRejectedValue(noResponseError("ERR_NETWORK"));
    renderProvider();
    expect(await screen.findByText("Session check failed: Could not reach the Warden API. Check your connection.")).toBeInTheDocument();
  });
});
