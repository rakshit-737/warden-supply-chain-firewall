import { describe, expect, it } from "vitest";
import { ALL_TOOLS_AVAILABLE, DEVELOPMENT_INFO, PRODUCTION_INFO, TOOLS } from "./fixtures";
import { assessPosture } from "./posture";
import { readToolStatuses } from "./systemInfo";

const ids = (info: unknown, tools = readToolStatuses(TOOLS)) => assessPosture(info, tools).observations.map((o) => o.id);

describe("assessPosture", () => {
  it("has nothing to note for a hardened production deployment", () => {
    const report = assessPosture(PRODUCTION_INFO, readToolStatuses(ALL_TOOLS_AVAILABLE));
    expect(report.observations).toEqual([]);
    expect(report.notAssessed).toEqual([]);
    expect(report.checked).toContain("metrics access");
  });

  it("notes development defaults, with the settings worth reviewing first", () => {
    const report = assessPosture(DEVELOPMENT_INFO, readToolStatuses(TOOLS));
    expect(report.observations.map((o) => o.id)).toEqual([
      "metrics-token",
      "cache-in-process",
      "tools-missing",
      "environment",
      "trusted-proxies",
    ]);
    const tools = report.observations.find((o) => o.id === "tools-missing");
    // gitleaks is unavailable too, but it is disabled by configuration, so it is not an observation.
    expect(tools?.title).toBe("semgrep is enabled but not available");
    expect(report.observations.every((o) => !/critical|danger|alert/i.test(`${o.title} ${o.detail}`))).toBe(true);
  });

  it("does not mention a metrics token when the metrics endpoint is off", () => {
    const info = { ...DEVELOPMENT_INFO, features: { ...DEVELOPMENT_INFO.features, metrics: { enabled: false, token_required: false } } };
    expect(ids(info)).not.toContain("metrics-token");
  });

  it("tells disabled and offline vulnerability intelligence apart", () => {
    const features = PRODUCTION_INFO.features;
    expect(ids({ ...PRODUCTION_INFO, features: { ...features, intel: { enabled: false, offline: false, nvd_enabled: false } } })).toContain("intel-disabled");
    expect(ids({ ...PRODUCTION_INFO, features: { ...features, intel: { enabled: true, offline: true, nvd_enabled: false } } })).toContain("intel-offline");
  });

  it("reports checks it could not make instead of assuming they passed", () => {
    expect(assessPosture(PRODUCTION_INFO, null).notAssessed).toEqual(["analysis tools"]);
    const empty = assessPosture({}, null);
    expect(empty.observations).toEqual([]);
    expect(empty.checked).toEqual([]);
    expect(empty.notAssessed).toHaveLength(8);
  });
});
