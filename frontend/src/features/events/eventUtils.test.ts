import { describe, expect, it } from "vitest";
import {
  readEventQuery,
  sinceBefore,
  validateEventTextFilters,
} from "./eventFilters";
import { eventTypeLabel, packageScansPath, scanPath } from "./eventLabels";
import { isUuid, parseOffset } from "./searchParams";
import { formatRelativeTime, formatTimestamp, fromLocalInputValue, toLocalInputValue } from "./time";

const NOW = Date.parse("2026-09-15T12:00:00Z");
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

describe("formatRelativeTime", () => {
  it("says just now within 45 seconds in either direction", () => {
    expect(formatRelativeTime("2026-09-15T11:59:30Z", NOW)).toBe("just now");
    expect(formatRelativeTime("2026-09-15T12:00:20Z", NOW)).toBe("just now");
  });

  it("uses the largest whole unit", () => {
    expect(formatRelativeTime("2026-09-15T11:55:00Z", NOW)).toBe(relative.format(-5, "minute"));
    expect(formatRelativeTime("2026-09-15T08:59:00Z", NOW)).toBe(relative.format(-3, "hour"));
    expect(formatRelativeTime("2026-09-13T12:00:00Z", NOW)).toBe(relative.format(-2, "day"));
  });

  it("returns null for values that are not timestamps", () => {
    expect(formatRelativeTime("", NOW)).toBeNull();
    expect(formatRelativeTime("yesterday-ish", NOW)).toBeNull();
    expect(formatRelativeTime(null, NOW)).toBeNull();
  });
});

describe("timestamps", () => {
  it("keeps unparseable text visible instead of inventing a date", () => {
    expect(formatTimestamp(null)).toBe("Not recorded");
    expect(formatTimestamp("not a date")).toBe("not a date");
  });

  it("converts datetime-local values to ISO and back in local time", () => {
    const iso = fromLocalInputValue("2026-09-10T08:30");
    expect(iso).not.toBeNull();
    expect(new Date(iso ?? "").getHours()).toBe(8);
    expect(toLocalInputValue(iso)).toBe("2026-09-10T08:30");
    expect(fromLocalInputValue("2026-02-30T08:00")).toBeNull();
    expect(fromLocalInputValue("2026-09-10")).toBeNull();
    expect(toLocalInputValue("garbage")).toBe("");
  });
});

describe("readEventQuery", () => {
  it("reads valid filters and reports invalid ones without using them", () => {
    const state = readEventQuery(
      new URLSearchParams(
        "type=PACKAGE_BLOCKED&severity=high&package=reqeusts&project_id=not-a-uuid&since=2026-09-01T00:00:00Z&acknowledged=maybe&offset=25",
      ),
    );
    expect(state.filters).toEqual({
      type: "package_blocked",
      severity: "high",
      package: "reqeusts",
      since: "2026-09-01T00:00:00.000Z",
    });
    expect(state.offset).toBe(25);
    expect(state.ignored).toEqual(["project_id", "acknowledged"]);
  });

  it("ignores offsets and times the server would refuse", () => {
    expect(readEventQuery(new URLSearchParams("offset=-1")).ignored).toEqual(["offset"]);
    expect(readEventQuery(new URLSearchParams("offset=2000000")).ignored).toEqual(["offset"]);
    expect(readEventQuery(new URLSearchParams("since=1")).ignored).toEqual(["since"]);
    expect(readEventQuery(new URLSearchParams("acknowledged=false")).filters).toEqual({ acknowledged: false });
  });
});

describe("validateEventTextFilters", () => {
  it("accepts empty fields as no filter", () => {
    expect(validateEventTextFilters({ package: " ", projectId: "", since: "" }, { now: NOW })).toEqual({
      errors: {},
      values: { package: null, projectId: null, since: null },
    });
  });

  it("requires a UUID project ID and a complete time that is not in the future", () => {
    const future = toLocalInputValue(new Date(NOW + 2 * 86_400_000).toISOString());
    const { errors } = validateEventTextFilters({ package: "requests", projectId: "project-1", since: future }, { now: NOW });
    expect(errors.projectId).toMatch(/UUID/);
    expect(errors.since).toMatch(/future/);
    const incomplete = validateEventTextFilters({ package: "", projectId: "", since: "" }, { now: NOW, sinceIncomplete: true });
    expect(incomplete.errors.since).toMatch(/complete/);
  });

  it("normalises accepted values", () => {
    const { errors, values } = validateEventTextFilters(
      { package: " requests ", projectId: "3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B", since: "" },
      { now: NOW },
    );
    expect(errors).toEqual({});
    expect(values).toEqual({ package: "requests", projectId: "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b", since: null });
  });
});

describe("helpers", () => {
  it("rounds quick ranges down to the minute", () => {
    expect(sinceBefore(3_600_000, NOW + 42_000)).toBe("2026-09-15T11:00:00.000Z");
  });

  it("parses offsets and UUIDs strictly", () => {
    expect(parseOffset(null)).toBe(0);
    expect(parseOffset("50")).toBe(50);
    expect(parseOffset("5e3")).toBeNull();
    expect(isUuid("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b")).toBe(true);
    expect(isUuid("3f2a9c1e5b7d4e8f9a0b1c2d3e4f5a6b")).toBe(false);
  });

  it("builds in-app links with encoded values and labels unknown event types readably", () => {
    expect(scanPath("a/../b")).toBe("/scans/a%2F..%2Fb");
    expect(packageScansPath("a&b=c")).toBe("/scans?q=a%26b%3Dc");
    expect(eventTypeLabel("kev_added")).toBe("Known exploited vulnerability added");
    expect(eventTypeLabel("future_event_type")).toBe("Future event type");
  });
});
