import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ConfidencePill } from "./ConfidencePill";
import { DecisionBadge } from "./DecisionBadge";
import { SeverityBadge } from "./SeverityBadge";

describe("SeverityBadge", () => {
  it("labels the severity and fills one pip per level", () => {
    const { container } = render(<SeverityBadge value="high" />);
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(container.querySelectorAll(".bg-sev-high")).toHaveLength(4);
  });

  it("shows Unknown with no filled pips for an unrecognised value", () => {
    const { container } = render(<SeverityBadge value="catastrophic" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(container.querySelectorAll('[class*="bg-sev-"]')).toHaveLength(0);
  });
});

describe("DecisionBadge", () => {
  it.each([
    ["allow", "Allow", "circle"],
    ["warn", "Warn", "path"],
    ["block", "Block", "path"],
  ] as const)("renders %s with a label and a shape", (value, label, shape) => {
    const { container } = render(<DecisionBadge value={value} />);
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(container.querySelector(`svg ${shape}`)).not.toBeNull();
    expect(container.firstElementChild).toHaveAttribute("data-decision", value);
  });

  it("does not guess a verdict for unknown values", () => {
    const { container } = render(<DecisionBadge value="quarantine" size="lg" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(container.firstElementChild).toHaveAttribute("data-decision", "unknown");
  });
});

describe("ConfidencePill", () => {
  it.each([
    [0.923, "92%", "strong"],
    [0.97, "97%", "deterministic"],
    [0.949, "95%", "deterministic"],
    [0.6, "60%", "heuristic"],
    [0.2, "20%", "weak"],
    [1.7, "100%", "deterministic"],
  ] as const)("shows %s as %s (%s)", (value, percent, tier) => {
    const { container } = render(<ConfidencePill value={value} />);
    expect(screen.getByText(percent)).toBeInTheDocument();
    expect(screen.getByText(tier)).toBeInTheDocument();
    expect(container.firstElementChild).toHaveAttribute("data-confidence", tier);
  });

  it("says unknown instead of 0% when confidence is missing", () => {
    const { container } = render(<ConfidencePill value={undefined} compact />);
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(screen.queryByText("0%")).toBeNull();
    expect(container.firstElementChild).toHaveAttribute("data-confidence", "unknown");
  });
});
