import { describe, expect, it } from "vitest";
import { compareFindings, confidenceBucket, confidencePercent, orderRiskDimensions, severityForScore } from "./risk";

describe("severityForScore", () => {
  it.each([
    [-5, "info"],
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
    [250, "critical"],
    [Number.NaN, "info"],
  ] as const)("maps %s to %s", (score, band) => {
    expect(severityForScore(score)).toBe(band);
  });
});

describe("confidence", () => {
  it("clamps to a whole percentage and is null when missing", () => {
    expect(confidencePercent(0.923)).toBe(92);
    expect(confidencePercent(1.4)).toBe(100);
    expect(confidencePercent(-1)).toBe(0);
    expect(confidencePercent(null)).toBeNull();
    expect(confidencePercent(Number.NaN)).toBeNull();
  });

  it.each([
    [100, "deterministic"],
    [95, "deterministic"],
    [94, "strong"],
    [80, "strong"],
    [79, "heuristic"],
    [50, "heuristic"],
    [49, "weak"],
    [0, "weak"],
  ] as const)("puts %i%% in the %s tier", (percent, tier) => {
    expect(confidenceBucket(percent)).toBe(tier);
  });
});

describe("compareFindings", () => {
  it("orders by severity, then confidence, then weight", () => {
    const findings = [
      { code: "LOW", severity: "low", confidence: 0.99, weight: 1 },
      { code: "CRIT_WEAK", severity: "critical", confidence: 0.5, weight: 9 },
      { code: "CRIT_STRONG", severity: "critical", confidence: 0.95, weight: 9 },
      { code: "CRIT_V1", severity: "critical", confidence: null, weight: 12 },
      { code: "ODD", severity: "unheard-of", confidence: 1, weight: 50 },
    ];
    expect([...findings].sort(compareFindings).map((f) => f.code)).toEqual(["CRIT_STRONG", "CRIT_WEAK", "CRIT_V1", "LOW", "ODD"]);
  });
});

describe("orderRiskDimensions", () => {
  it("uses the spec order, appends unknown dimensions and skips malformed entries", () => {
    const ordered = orderRiskDimensions({
      zeta: { score: 1, confidence: 1, contributors: [], rationale: null },
      vulnerability: { score: null, confidence: 0, contributors: [], rationale: null },
      behavioral: { score: 70, confidence: 0.8, contributors: [], rationale: null },
      integrity: "broken",
    });
    expect(ordered.map((entry) => entry.name)).toEqual(["behavioral", "vulnerability", "zeta"]);
    expect(orderRiskDimensions(null)).toEqual([]);
    expect(orderRiskDimensions([1, 2])).toEqual([]);
  });
});
