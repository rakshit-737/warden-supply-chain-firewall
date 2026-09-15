import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { KeyValueList } from "./KeyValueList";
import { LoadingBlock, Skeleton } from "./Skeleton";
import { Timeline } from "./Timeline";

describe("EmptyState", () => {
  it("shows the message and an action", () => {
    render(<EmptyState title="No scans yet." description="Start one with New scan." action={<button type="button">New scan</button>} />);
    expect(screen.getByText("No scans yet.")).toBeInTheDocument();
    expect(screen.getByText("Start one with New scan.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New scan" })).toBeInTheDocument();
  });
});

describe("ErrorState", () => {
  it("announces the failure with status, request id and a retry", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    render(
      <ErrorState
        title="Scan statistics could not be loaded"
        error={{ status: 503, code: "unavailable", message: "Database unavailable.", requestId: "req-42" }}
        onRetry={onRetry}
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Scan statistics could not be loaded");
    expect(alert).toHaveTextContent("Database unavailable.");
    expect(alert).toHaveTextContent("HTTP 503");
    expect(alert).toHaveTextContent("req-42");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("accepts a plain message", () => {
    render(<ErrorState error="Something failed." />);
    expect(screen.getByRole("alert")).toHaveTextContent("Something failed.");
    expect(screen.queryByRole("button")).toBeNull();
  });
});

describe("Skeleton and LoadingBlock", () => {
  it("hides placeholder shapes from assistive technology but announces loading", () => {
    const { container } = render(
      <>
        <Skeleton className="h-4" />
        <LoadingBlock label="Loading scans" rows={2} />
      </>,
    );
    expect(container.firstElementChild).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByRole("status")).toHaveTextContent("Loading scans");
  });
});

describe("KeyValueList", () => {
  it("renders terms with explicit text for missing and boolean values", () => {
    render(
      <KeyValueList
        items={[
          { term: "Model", value: null },
          { term: "Attested", value: true },
          { term: "Findings", value: 0 },
          { term: "Workflow", value: "release.yml", mono: true },
        ]}
      />,
    );
    expect(screen.getAllByRole("term")).toHaveLength(4);
    expect(screen.getByText("Not recorded")).toBeInTheDocument();
    expect(screen.getByText("Yes")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText("release.yml")).toHaveClass("font-mono");
  });
});

describe("Timeline", () => {
  it("lists entries in the given order with machine-readable times", () => {
    render(
      <Timeline
        label="Security events"
        items={[
          { id: "2", title: "Blocked reqeusts==1.0.0", time: "2026-09-02T08:00:00Z", tone: "critical" },
          { id: "1", title: "Scanned requests==2.32.3", time: "2026-09-01T08:00:00Z", description: "Allowed" },
        ]}
      />,
    );
    const items = within(screen.getByRole("list", { name: "Security events" })).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("Blocked reqeusts==1.0.0");
    expect(items[0]?.querySelector("time")).toHaveAttribute("datetime", "2026-09-02T08:00:00Z");
    expect(items[1]).toHaveTextContent("Allowed");
  });
});
