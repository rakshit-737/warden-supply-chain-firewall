import { describe, expect, it } from "vitest";
import { PRODUCTION_INFO, TOOLS } from "./fixtures";
import { formatBytes, formatSeconds, formatSetting, readToolStatuses, unlistedSettings } from "./systemInfo";

describe("formatBytes and formatSeconds", () => {
  it("uses binary units and whole minutes where they are exact", () => {
    expect(formatBytes(4 * 1024 * 1024)).toBe("4 MiB");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(512)).toBe("512 bytes");
    expect(formatSeconds(180)).toBe("3 minutes");
    expect(formatSeconds(90)).toBe("90 seconds");
    expect(formatSeconds(1)).toBe("1 second");
  });
});

describe("formatSetting", () => {
  it("formats switches and marks missing values instead of guessing", () => {
    expect(formatSetting("switch", true)).toEqual({ text: "On", tone: "on", mono: false });
    expect(formatSetting("switch", false)).toMatchObject({ text: "Off", tone: "off" });
    expect(formatSetting("switch", undefined)).toMatchObject({ text: "Not reported", tone: "missing" });
    expect(formatSetting("cacheBackend", "in_process").text).toBe("In-process, separate for each API process");
    expect(formatSetting("perMinute", 120).text).toBe("120 per minute");
  });

  it("shows a value of an unexpected type as text rather than hiding it", () => {
    expect(formatSetting("switch", "yes")).toMatchObject({ text: "yes", tone: "plain", mono: true });
    expect(formatSetting("bytes", -1)).toMatchObject({ text: "-1", mono: true });
  });

  it("makes invisible control characters in reported text visible", () => {
    expect(formatSetting("version", "2.0‮1").text).toBe("2.0<U+202E>1");
  });
});

describe("unlistedSettings", () => {
  it("describes every value the current backend reports", () => {
    expect(unlistedSettings(PRODUCTION_INFO)).toEqual([]);
  });

  it("still lists values a newer server adds", () => {
    const info = { ...PRODUCTION_INFO, features: { ...PRODUCTION_INFO.features, sigstore: { enabled: true } }, region: "eu" };
    expect(unlistedSettings(info).map((row) => row.key)).toEqual(["features.sigstore.enabled", "region"]);
  });
});

describe("readToolStatuses", () => {
  it("keeps named entries and treats anything but true as unavailable", () => {
    const rows = readToolStatuses([...TOOLS, { name: "", available: true }, "trivy", { name: "trivy", available: "yes" }]);
    expect(rows.map((row) => [row.name, row.available])).toEqual([
      ["yara", true],
      ["semgrep", false],
      ["gitleaks", false],
      ["syft", true],
      ["trivy", false],
    ]);
    expect(readToolStatuses({ tools: TOOLS })).toEqual([]);
  });
});
