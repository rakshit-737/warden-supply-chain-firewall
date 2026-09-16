import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { acknowledgeEvent, listEvents } from "../api/events";
import type { Page, Role, SecurityEvent } from "../api/types";
import { AuthContext } from "../auth/context";
import { makeAuthState } from "../test/auth";
import { httpError } from "../test/http";
import Events from "./Events";

vi.mock("../api/events", () => ({ listEvents: vi.fn(), acknowledgeEvent: vi.fn() }));

// Test fixtures: hand-written events, not data from a deployment.
const HOSTILE = '<img src=x onerror="alert(1)">';
const BLOCKED: SecurityEvent = {
  id: "0b6f1d52-3f8e-4a4b-9a55-0d1f4f7c2a01",
  type: "package_blocked",
  severity: "critical",
  title: "Blocked reqeusts==2.31.0",
  package: "reqeusts",
  version: "2.31.0",
  project_id: "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b",
  scan_id: "5d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6",
  details: { decision: "block", risk_score: 92, matched_rules: ["deny:typosquatting"], note: HOSTILE },
  created_at: "2026-09-15T11:55:00Z",
  acknowledged: false,
  acknowledged_by: null,
  acknowledged_at: null,
};
const DRIFT: SecurityEvent = {
  ...BLOCKED,
  id: "0b6f1d52-3f8e-4a4b-9a55-0d1f4f7c2a02",
  type: "behavior_drift_detected",
  severity: "medium",
  title: "Behaviour drift in example-lib 1.4.0",
  package: "example-lib",
  version: "1.4.0",
  project_id: null,
  scan_id: null,
  details: {},
  acknowledged: true,
  acknowledged_by: "user-2",
  acknowledged_at: "2026-09-15T11:58:00Z",
};

function pageOf(items: SecurityEvent[]): Page<SecurityEvent> {
  return { items, total: items.length, limit: 25, offset: 0 };
}

function deferred<T>() {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function LocationProbe() {
  return <output aria-label="Current search">{useLocation().search}</output>;
}

function renderEvents(role: Role, path = "/events") {
  render(
    <AuthContext.Provider value={makeAuthState(role)}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/events"
            element={
              <>
                <Events />
                <LocationProbe />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

const blockedTitle = () => screen.findByRole("button", { name: "Blocked reqeusts==2.31.0" });

describe("Events", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.mocked(listEvents).mockReset().mockResolvedValue(pageOf([BLOCKED, DRIFT]));
    vi.mocked(acknowledgeEvent).mockReset();
  });

  it("sends the filters in the address to the server and reports the invalid ones it left out", async () => {
    renderEvents(
      "read_only",
      "/events?type=package_blocked&severity=critical&package=reqeusts&project_id=nope&since=2026-09-01T00:00:00Z&acknowledged=false",
    );
    expect(await blockedTitle()).toBeInTheDocument();
    expect(listEvents).toHaveBeenCalledWith(
      {
        limit: 25,
        offset: 0,
        type: "package_blocked",
        severity: "critical",
        package: "reqeusts",
        since: "2026-09-01T00:00:00.000Z",
        acknowledged: false,
      },
      expect.anything(),
    );
    expect(screen.getByText(/not applied: project ID\./)).toBeInTheDocument();
    expect(screen.getByLabelText("Package")).toHaveValue("reqeusts");
  });

  it("applies a select filter at once and returns to the first page", async () => {
    const user = userEvent.setup();
    renderEvents("read_only", "/events?offset=25");
    await blockedTitle();

    await user.selectOptions(screen.getByLabelText("Severity"), "critical");

    await waitFor(() => expect(screen.getByLabelText("Current search")).toHaveTextContent(/^\?severity=critical$/));
    expect(listEvents).toHaveBeenLastCalledWith(expect.objectContaining({ severity: "critical", offset: 0 }), expect.anything());
  });

  it("refuses an invalid project ID without sending it, and says why", async () => {
    const user = userEvent.setup();
    renderEvents("read_only");
    await blockedTitle();

    const project = screen.getByLabelText("Project ID");
    await user.type(project, "project-1");
    await user.click(screen.getByRole("button", { name: "Apply filters" }));

    expect(screen.getByRole("alert")).toHaveTextContent("The filters were not applied. Correct the highlighted field.");
    expect(project).toHaveFocus();
    expect(project).toHaveAttribute("aria-invalid", "true");
    expect(project).toHaveAccessibleDescription(/UUID/);
    expect(listEvents).toHaveBeenCalledTimes(1);

    await user.clear(project);
    await user.type(project, "3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B{Enter}");
    await waitFor(() =>
      expect(screen.getByLabelText("Current search")).toHaveTextContent("project_id=3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"),
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("refuses a since time in the future", async () => {
    const user = userEvent.setup();
    renderEvents("read_only");
    await blockedTitle();

    const since = screen.getByLabelText("Since (your local time)");
    fireEvent.change(since, { target: { value: "2099-01-01T00:00" } });
    await user.click(screen.getByRole("button", { name: "Apply filters" }));

    expect(since).toHaveFocus();
    expect(since).toHaveAccessibleDescription("Choose a time that is not in the future.");
    expect(screen.getByLabelText("Current search")).toHaveTextContent(/^$/);
  });

  it("does not offer acknowledgement to a role without event:ack", async () => {
    renderEvents("read_only");
    await blockedTitle();
    expect(screen.queryByRole("button", { name: /^Acknowledge/ })).toBeNull();
    expect(within(screen.getByRole("row", { name: /Blocked reqeusts/ })).getByText("Unacknowledged")).toBeInTheDocument();
    expect(within(screen.getByRole("row", { name: /Behaviour drift/ })).getByText("Acknowledged")).toBeInTheDocument();
  });

  it("does not load events for a role it does not recognise", async () => {
    renderEvents("guest" as Role);
    expect(await screen.findByRole("heading", { name: "Access restricted" })).toBeInTheDocument();
    expect(listEvents).not.toHaveBeenCalled();
  });

  it("acknowledges optimistically, ignores repeat clicks and keeps focus on the control", async () => {
    const user = userEvent.setup();
    const pending = deferred<SecurityEvent>();
    vi.mocked(acknowledgeEvent).mockReturnValue(pending.promise);
    renderEvents("security_analyst");

    const button = await screen.findByRole("button", { name: /^Acknowledge event Blocked reqeusts/ });
    await user.click(button);

    expect(button).toHaveTextContent(/^Acknowledging/);
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).toHaveFocus();
    await user.click(button);
    expect(acknowledgeEvent).toHaveBeenCalledTimes(1);
    expect(acknowledgeEvent).toHaveBeenCalledWith(BLOCKED.id);

    await act(async () => {
      pending.resolve({ ...BLOCKED, acknowledged: true, acknowledged_by: "user-1", acknowledged_at: "2026-09-15T12:00:00Z" });
      await pending.promise;
    });
    expect(button).toHaveTextContent(/^Acknowledged/);
    expect(button).toHaveFocus();
    expect(screen.getByText("Acknowledged: Blocked reqeusts==2.31.0")).toBeInTheDocument();
  });

  it("rolls the acknowledgement back and shows the server's reason when it fails", async () => {
    const user = userEvent.setup();
    vi.mocked(acknowledgeEvent).mockRejectedValue(
      httpError(403, {
        data: { error: { code: "forbidden", message: "Missing required permission: event:ack", request_id: "req-7" } },
      }),
    );
    renderEvents("security_analyst");

    const button = await screen.findByRole("button", { name: /^Acknowledge event Blocked reqeusts/ });
    await user.click(button);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Not acknowledged: Blocked reqeusts==2.31.0");
    expect(alert).toHaveTextContent("Missing required permission: event:ack");
    expect(alert).toHaveTextContent("req-7");
    expect(button).toHaveTextContent(/^Acknowledge event/);
    expect(button).not.toHaveAttribute("aria-disabled");

    await user.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows details as plain text in a dialog, links the scan and returns focus on Escape", async () => {
    const user = userEvent.setup();
    renderEvents("read_only");
    const opener = await blockedTitle();

    await user.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Blocked reqeusts==2.31.0" });
    expect(within(dialog).getByRole("heading", { name: "Blocked reqeusts==2.31.0" })).toHaveFocus();
    expect(within(dialog).getByText("risk_score")).toBeInTheDocument();
    expect(within(dialog).getAllByText(HOSTILE).length).toBeGreaterThan(0);
    expect(document.querySelector("img")).toBeNull();
    expect(within(dialog).getByRole("link", { name: "Open the scan" })).toHaveAttribute("href", `/scans/${BLOCKED.scan_id}`);

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(opener).toHaveFocus();

    await user.click(opener);
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Show only events for reqeusts" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(screen.getByLabelText("Current search")).toHaveTextContent("?package=reqeusts"));
  });

  it("shows the server's error with a retry, and an empty state", async () => {
    const user = userEvent.setup();
    vi.mocked(listEvents)
      .mockRejectedValueOnce(httpError(503, { data: { error: { code: "unavailable", message: "Database unavailable.", request_id: "req-1" } } }))
      .mockResolvedValue(pageOf([]));
    renderEvents("read_only");

    expect(await screen.findByRole("alert")).toHaveTextContent("Database unavailable.");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("No security events recorded yet.")).toBeInTheDocument();
  });

  it("polls every 30 seconds while auto-refresh is on, and stops when it is turned off", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      renderEvents("read_only");
      await blockedTitle();
      expect(listEvents).toHaveBeenCalledTimes(1);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
      });
      await waitFor(() => expect(listEvents).toHaveBeenCalledTimes(2));

      fireEvent.click(screen.getByRole("switch", { name: "Auto-refresh" }));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(90_000);
      });
      expect(listEvents).toHaveBeenCalledTimes(2);
      expect(window.localStorage.getItem("warden.events.auto-refresh")).toBe("off");
    } finally {
      vi.useRealTimers();
    }
  });
});
