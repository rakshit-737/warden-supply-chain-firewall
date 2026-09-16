import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listAuditEvents, verifyAuditChain } from "../api/audit";
import type { AuditEvent, AuditVerifyResult, Page, Role } from "../api/types";
import { AuthContext } from "../auth/context";
import { formatInteger } from "../features/audit/verifyResult";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import Audit from "./Audit";

vi.mock("../api/audit", () => ({ listAuditEvents: vi.fn(), verifyAuditChain: vi.fn() }));

// Test fixtures: hand-written audit records, not data from a deployment.
const ACTOR = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const HOSTILE = "<script>alert(1)</script>";
const POLICY_UPDATE: AuditEvent = {
  id: "c1d2e3f4-0000-4000-8000-000000000042",
  actor_id: ACTOR,
  action: "policy.update",
  target_type: "policy",
  target_id: "c56a4180-65aa-42ec-a945-5fd21dec0538",
  metadata: { version: 3, environment: "production", changes: { warn_threshold: { before: 40, after: 45 } }, comment: HOSTILE },
  request_id: "req-2f9c4e1d7a3b5c6d",
  created_at: "2026-09-15T11:50:00Z",
  seq: 42,
  prev_hash: "a".repeat(64),
  event_hash: "b".repeat(64),
};
const LOGIN_FAILED: AuditEvent = {
  ...POLICY_UPDATE,
  id: "c1d2e3f4-0000-4000-8000-000000000041",
  actor_id: null,
  action: "user.login_failed",
  target_type: "user",
  target_id: null,
  metadata: { email: "someone@example.test", reason: "bad_password" },
  request_id: null,
  seq: 41,
};
const VERIFIED_AT = "2026-09-15T12:00:00Z";

function pageOf(items: AuditEvent[]): Page<AuditEvent> {
  return { items, total: items.length, limit: 25, offset: 0 };
}

function LocationProbe() {
  return <output aria-label="Current search">{useLocation().search}</output>;
}

function renderAudit(role: Role, path = "/audit") {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/audit"
            element={
              <>
                <Audit />
                <LocationProbe />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe("Audit", () => {
  beforeEach(() => {
    vi.mocked(listAuditEvents).mockReset().mockResolvedValue(pageOf([POLICY_UPDATE, LOGIN_FAILED]));
    vi.mocked(verifyAuditChain).mockReset();
  });

  it("keeps roles without audit:read out without requesting anything", async () => {
    renderAudit("developer");
    expect(await screen.findByRole("heading", { name: "Access restricted" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Verify integrity" })).toBeNull();
    expect(listAuditEvents).not.toHaveBeenCalled();
    expect(verifyAuditChain).not.toHaveBeenCalled();
  });

  it("lists entries for an auditor with the filters from the address", async () => {
    renderAudit("auditor", `/audit?action=policy.update&actor_id=${ACTOR.toUpperCase()}&target_type=policy&offset=abc`);

    expect(await screen.findByRole("button", { name: /^policy\.update/ })).toBeInTheDocument();
    expect(listAuditEvents).toHaveBeenCalledWith(
      { limit: 25, offset: 0, action: "policy.update", actor_id: ACTOR, target_type: "policy" },
      expect.anything(),
    );
    expect(screen.getByText(/not applied: page\./)).toBeInTheDocument();
    const failedRow = screen.getByRole("row", { name: /user\.login_failed/ });
    expect(within(failedRow).getByText("No signed-in user")).toBeInTheDocument();
    expect(screen.getByLabelText("Actor ID")).toHaveValue(ACTOR);
  });

  it("refuses an actor ID that is not a UUID and says why", async () => {
    const user = userEvent.setup();
    renderAudit("auditor");
    await screen.findByRole("button", { name: /^policy\.update/ });

    const actor = screen.getByLabelText("Actor ID");
    await user.type(actor, "alice{Enter}");

    expect(screen.getByRole("alert")).toHaveTextContent("The filters were not applied.");
    expect(actor).toHaveFocus();
    expect(actor).toHaveAccessibleDescription(/UUID/);
    expect(listAuditEvents).toHaveBeenCalledTimes(1);

    await user.clear(screen.getByLabelText("Action"));
    await user.clear(actor);
    await user.type(screen.getByLabelText("Action"), "user.login_failed{Enter}");
    await waitFor(() => expect(screen.getByLabelText("Current search")).toHaveTextContent("?action=user.login_failed"));
  });

  it("shows an entry's metadata as plain text and filters by its actor", async () => {
    const user = userEvent.setup();
    renderAudit("admin");
    await user.click(await screen.findByRole("button", { name: /^policy\.update/ }));

    const dialog = screen.getByRole("dialog", { name: "policy.update" });
    expect(within(dialog).getByText(HOSTILE)).toBeInTheDocument();
    expect(dialog.querySelector("script")).toBeNull();
    expect(within(dialog).getByText("b".repeat(64))).toBeInTheDocument();
    expect(within(dialog).getByText("req-2f9c4e1d7a3b5c6d")).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Only entries by this actor" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(screen.getByLabelText("Current search")).toHaveTextContent(`?actor_id=${ACTOR}`));
  });

  it("reports an intact chain with its count, head and verification time, next to an honest note", async () => {
    const user = userEvent.setup();
    const result: AuditVerifyResult = {
      ok: true,
      checked: 1284,
      first_broken_seq: null,
      reason: null,
      head_seq: 1284,
      head_hash: "c".repeat(64),
      verified_at: VERIFIED_AT,
    };
    vi.mocked(verifyAuditChain).mockResolvedValue(result);
    renderAudit("auditor");

    expect(screen.getByText("Tamper-evident, not tamper-proof")).toBeInTheDocument();
    expect(screen.getByText(/deleting the newest events leaves a shorter chain that still verifies/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Verify integrity" }));

    const panel = screen.getByRole("region", { name: "Hash chain integrity" });
    expect(await within(panel).findByText("Chain intact")).toBeInTheDocument();
    expect(within(panel).getByText(formatInteger(1284), { selector: "dd" })).toBeInTheDocument();
    expect(within(panel).getByText("Head seq")).toBeInTheDocument();
    expect(within(panel).getByText("c".repeat(64))).toBeInTheDocument();
    expect(within(panel).getByText("Verified at").nextElementSibling?.querySelector("time")).toHaveAttribute("datetime", VERIFIED_AT);
    expect(within(panel).getByRole("button", { name: "Verify again" })).toBeInTheDocument();
  });

  it("names the first broken event and the server's reason", async () => {
    const user = userEvent.setup();
    vi.mocked(verifyAuditChain).mockResolvedValue({
      ok: false,
      checked: 41,
      first_broken_seq: 42,
      reason: "event_hash mismatch: stored event content was modified",
      head_seq: 41,
      head_hash: "d".repeat(64),
      verified_at: VERIFIED_AT,
    });
    renderAudit("auditor");

    await user.click(screen.getByRole("button", { name: "Verify integrity" }));

    const panel = screen.getByRole("region", { name: "Hash chain integrity" });
    expect(await within(panel).findByText("Broken at seq 42")).toBeInTheDocument();
    expect(within(panel).getByText("event_hash mismatch: stored event content was modified")).toBeInTheDocument();
    expect(within(panel).getByText("Last verified seq").nextElementSibling).toHaveTextContent("41");
    expect(within(panel).getByText("First broken seq").nextElementSibling).toHaveTextContent("42");
    expect(within(panel).queryByText("Chain intact")).toBeNull();
  });

  it("does not start a second run while verifying, and offers a retry when verification fails", async () => {
    const user = userEvent.setup();
    let fail: (reason: unknown) => void = () => undefined;
    vi.mocked(verifyAuditChain)
      .mockImplementationOnce(
        () =>
          new Promise<AuditVerifyResult>((_, reject) => {
            fail = reject;
          }),
      )
      .mockResolvedValue({
        ok: true,
        checked: 2,
        first_broken_seq: null,
        reason: null,
        head_seq: 2,
        head_hash: "e".repeat(64),
        verified_at: VERIFIED_AT,
      });
    renderAudit("auditor");

    const button = screen.getByRole("button", { name: "Verify integrity" });
    await user.click(button);
    expect(button).toHaveTextContent("Verifying");
    await user.click(button);
    expect(verifyAuditChain).toHaveBeenCalledTimes(1);

    fail(httpError(503, { data: { error: { code: "unavailable", message: "Database unavailable.", request_id: "req-9" } } }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The chain could not be verified");
    expect(alert).toHaveTextContent("Database unavailable.");

    await user.click(within(alert).getByRole("button", { name: "Verify again" }));
    expect(await screen.findByText("Chain intact")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
