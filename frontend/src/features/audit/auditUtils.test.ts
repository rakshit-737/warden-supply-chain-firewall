import { describe, expect, it } from "vitest";
import type { AuditVerifyResult } from "../../api/types";
import { readAuditQuery, shortId, validateAuditFilters } from "./auditFilters";
import { describeVerification, formatInteger } from "./verifyResult";

const BASE: AuditVerifyResult = {
  ok: true,
  checked: 0,
  first_broken_seq: null,
  reason: null,
  head_seq: null,
  head_hash: null,
  verified_at: "2026-09-15T12:00:00Z",
};

describe("describeVerification", () => {
  it("reports an intact chain with the exact count", () => {
    const verdict = describeVerification({ ...BASE, checked: 12_840, head_seq: 12_840, head_hash: "c".repeat(64) });
    expect(verdict.kind).toBe("intact");
    expect(verdict.headline).toBe("Chain intact");
    expect(verdict.summary).toContain(formatInteger(12_840));
    expect(verdict.headSeq).toBe(12_840);
  });

  it("reports an empty trail as nothing to verify rather than as intact", () => {
    expect(describeVerification(BASE).kind).toBe("empty");
  });

  it("names the first broken event", () => {
    const verdict = describeVerification({
      ...BASE,
      ok: false,
      checked: 41,
      first_broken_seq: 42,
      reason: "event_hash mismatch: stored event content was modified",
      head_seq: 41,
    });
    expect(verdict.kind).toBe("broken");
    expect(verdict.headline).toBe("Broken at seq 42");
    expect(verdict.summary).toMatch(/^41 events before it verified/);
    expect(verdict.reason).toBe("event_hash mismatch: stored event content was modified");
  });

  it("reports a break that is not tied to one event, and never trusts a malformed ok", () => {
    const unlocated = describeVerification({
      ...BASE,
      ok: false,
      checked: 7,
      reason: "3 audit event(s) are not part of the hash chain",
    });
    expect(unlocated.kind).toBe("unlocated");
    expect(unlocated.headline).toBe("Chain broken");
    const malformed = describeVerification({ ...BASE, ok: "true" as unknown as boolean, checked: 3 });
    expect(malformed.ok).toBe(false);
  });
});

describe("audit filters", () => {
  it("reads the address and drops invalid values", () => {
    const state = readAuditQuery(
      new URLSearchParams(`action=policy.update&actor_id=nobody&target_type=${"x".repeat(41)}&offset=abc`),
    );
    expect(state.filters).toEqual({ action: "policy.update" });
    expect(state.offset).toBe(0);
    expect(state.ignored).toEqual(["actor_id", "target_type", "offset"]);
  });

  it("validates a draft", () => {
    const invalid = validateAuditFilters({ action: "a".repeat(81), actorId: "alice", targetType: "" });
    expect(Object.keys(invalid.errors)).toEqual(["action", "actorId"]);
    const valid = validateAuditFilters({ action: " user.login ", actorId: "7C9E6679-7425-40DE-944B-E07FC1F90AE7", targetType: "" });
    expect(valid.errors).toEqual({});
    expect(valid.values).toEqual({ action: "user.login", actorId: "7c9e6679-7425-40de-944b-e07fc1f90ae7", targetType: null });
  });

  it("shortens long identifiers only", () => {
    expect(shortId("7c9e6679-7425-40de-944b-e07fc1f90ae7")).toBe("7c9e6679…");
    expect(shortId("req-1")).toBe("req-1");
  });
});
