import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Sparkline, StatTile } from "./StatTile";

describe("StatTile", () => {
  it("judges a change by which direction is better", () => {
    render(<StatTile label="Blocked packages" value={42} delta={{ value: 12, period: "previous 30 days", better: "down" }} />);
    expect(screen.getByText("Blocked packages")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("+12")).toBeInTheDocument();
    expect(screen.getByText("vs previous 30 days")).toBeInTheDocument();
    expect(screen.getByText("(a deterioration)")).toBeInTheDocument();
    expect(screen.getByText("+12").parentElement).toHaveAttribute("data-trend", "worse");
  });

  it("stays neutral when no direction is better", () => {
    render(<StatTile label="Scans" value="1.2K" delta={{ value: -3, period: "last week" }} />);
    expect(screen.getByText("-3").parentElement).toHaveAttribute("data-trend", "neutral");
  });

  it("renders a sparkline in its slot", () => {
    const { container } = render(<StatTile label="Scans" value={7} sparkline={<Sparkline values={[1, 4, 2, 8]} />} />);
    expect(container.querySelector("polyline")).not.toBeNull();
  });

  it("draws no sparkline from fewer than two points", () => {
    const { container } = render(<Sparkline values={[3, Number.NaN]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
