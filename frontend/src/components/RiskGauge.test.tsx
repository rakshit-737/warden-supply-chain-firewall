import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RiskBreakdownBars } from "./RiskBreakdownBars";
import { RiskGauge } from "./RiskGauge";
import { within } from "@testing-library/react";

describe("RiskGauge", () => {
  it.each([
    [0, "info"],
    [14, "info"],
    [15, "low"],
    [34, "low"],
    [35, "medium"],
    [59, "medium"],
    [60, "high"],
    [79, "high"],
    [80, "critical"],
    [100, "critical"],
  ] as const)("puts %i in the %s band", (score, band) => {
    render(<RiskGauge score={score} />);
    const meter = screen.getByRole("meter", { name: "Risk score" });
    expect(meter).toHaveAttribute("data-band", band);
    expect(meter).toHaveAttribute("aria-valuenow", String(score));
    expect(meter.getAttribute("aria-valuetext")).toContain(band);
  });

  it("clamps out-of-range scores", () => {
    render(<RiskGauge score={140.2} label="Final risk score" />);
    expect(screen.getByRole("meter", { name: "Final risk score" })).toHaveAttribute("aria-valuenow", "100");
  });

  it("shows Unknown rather than zero when there is no score", () => {
    render(<RiskGauge score={null} />);
    expect(screen.queryByRole("meter")).toBeNull();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });
});

describe("RiskBreakdownBars", () => {
  it("lists dimensions in spec order, with unknown scores and confidence", () => {
    render(
      <RiskBreakdownBars
        dimensions={{
          zeta_custom: { score: 10, confidence: 0.5, contributors: [], rationale: null },
          vulnerability: {
            score: null,
            confidence: 0,
            contributors: [],
            rationale: "Vulnerability intelligence was unavailable",
          },
          behavioral: { score: 72.4, confidence: 0.85, contributors: ["f1"], rationale: null },
          integrity: "not an object",
        }}
      />,
    );
    const rows = within(screen.getByRole("list", { name: "Risk dimensions" })).getAllByRole("listitem");
    expect(rows.map((row) => row.getAttribute("data-dimension"))).toEqual(["behavioral", "vulnerability", "zeta_custom"]);
    expect(rows[0]).toHaveTextContent("72");
    expect(rows[0]).toHaveTextContent("85%");
    expect(rows[1]).toHaveTextContent("unknown");
    expect(rows[1]).toHaveTextContent("Vulnerability intelligence was unavailable");
  });

  it("explains when no dimensions were recorded", () => {
    render(<RiskBreakdownBars dimensions={null} />);
    expect(screen.getByText("No risk dimensions were recorded.")).toBeInTheDocument();
  });
});
