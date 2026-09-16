import { describe, expect, it } from "vitest";
import {
  EMPTY_EXCEPTION_FORM,
  checkExpiry,
  checkVersionSpec,
  codesError,
  commentError,
  expiryBounds,
  justificationError,
  localDateString,
  normalizePackageName,
  packageNameError,
  parseLocalDate,
  validateExceptionForm,
} from "./validation";

const DAY_MS = 86_400_000;
// A fixed clock (local 10:30 on 15 September 2026) keeps the date checks deterministic.
const NOW = new Date(2026, 8, 15, 10, 30).getTime();

describe("package names", () => {
  it.each(["requests", "Requests_OAuthlib", "zope.interface", "a", "x1-y2.z3", "A".repeat(214)])("accepts %s", (name) => {
    expect(packageNameError(name)).toBeNull();
  });

  it.each(["", "   ", "../../etc/passwd", "evil pkg; rm -rf /", "-leading", "trailing.", "naïve", "A".repeat(215)])(
    "rejects %j",
    (name) => {
      expect(packageNameError(name)).not.toBeNull();
    },
  );

  it("ignores surrounding whitespace like the server", () => {
    expect(packageNameError("  requests ")).toBeNull();
  });

  it("normalises like PEP 503", () => {
    expect(normalizePackageName("  Exc_Pkg.__Name-- ")).toBe("exc-pkg-name-");
    expect(normalizePackageName("Requests_OAuthlib")).toBe("requests-oauthlib");
  });
});

describe("version specifiers", () => {
  // Outcomes recorded from packaging 26.0's SpecifierSet, the parser the server uses.
  it.each([
    ["<2.0", "<2.0"],
    [">=1.0, <2.0", ">=1.0,<2.0"],
    ["==1.*", "==1.*"],
    ["!=1.2.*", "!=1.2.*"],
    ["~=1.4", "~=1.4"],
    ["==1.0+local", "==1.0+local"],
    ["===foo", "===foo"],
    [">= 1.0", ">=1.0"],
    ["==v1.0", "==v1.0"],
    [">=1.0a1", ">=1.0a1"],
    [">=1.0.post1", ">=1.0.post1"],
    [">=1.0.dev0", ">=1.0.dev0"],
    ["==1!2.0", "==1!2.0"],
    [">=1.0-1", ">=1.0-1"],
    ["<=2.0rc1", "<=2.0rc1"],
    [">1.0,,<2", ">1.0,<2"],
    ["~=1.4.5a1", "~=1.4.5a1"],
    ["==1.0.dev0+abc", "==1.0.dev0+abc"],
  ])("accepts %j", (input, normalised) => {
    expect(checkVersionSpec(input)).toEqual({ ok: true, value: normalised });
  });

  it.each([
    "~=1",
    ">=1.0+local",
    "<1.*",
    "1.0",
    " , ",
    "v1",
    "=>1.0",
    "==1.0.*.1",
    "~=1.0.*",
    "==1.*+local",
    ">=1..0",
    ">=",
    "==1.0 extra",
    "<2.0;",
    "(>=1)",
    "latest please",
  ])("rejects %j", (input) => {
    expect(checkVersionSpec(input).ok).toBe(false);
  });

  it("treats an empty specifier as every version", () => {
    expect(checkVersionSpec("   ")).toEqual({ ok: true, value: null });
  });

  it("enforces the 100 character limit", () => {
    expect(checkVersionSpec(`<${"1.".repeat(50)}0`).ok).toBe(false);
  });
});

describe("justification and comments", () => {
  it("requires at least 10 characters after trimming", () => {
    expect(justificationError("")).toMatch(/Explain why/);
    expect(justificationError(" ".repeat(50))).toMatch(/Explain why/);
    expect(justificationError("too short")).toMatch(/at least 10/);
    expect(justificationError("  long enough  ")).toBeNull();
    expect(justificationError("x".repeat(2001))).toMatch(/at most 2000/);
  });

  it("counts code points like the server", () => {
    // Ten astral characters are 20 UTF-16 units but only 10 code points.
    expect(justificationError("😀".repeat(10))).toBeNull();
    expect(justificationError("😀".repeat(2000))).toBeNull();
  });

  it("requires a comment of at most 500 characters", () => {
    expect(commentError("   ")).not.toBeNull();
    expect(commentError("Reviewed with platform")).toBeNull();
    expect(commentError("x".repeat(501))).toMatch(/at most 500/);
  });
});

describe("scope", () => {
  it("refuses non-overridable codes and more than 50 codes", () => {
    expect(codesError(["NETWORK_EGRESS"])).toBeNull();
    expect(codesError(["IOC_MATCH"])).toMatch(/non-overridable/);
    expect(codesError(["hash_mismatch"])).toMatch(/non-overridable/);
    expect(codesError(Array.from({ length: 51 }, (_, i) => `CODE_${i}`))).toMatch(/at most 50/);
  });
});

describe("expiry", () => {
  it("offers dates from tomorrow to 365 days ahead", () => {
    expect(expiryBounds(NOW)).toEqual({ min: "2026-09-16", max: "2027-09-15" });
  });

  it("requires a future date at most 365 days ahead", () => {
    expect(checkExpiry("", NOW).ok).toBe(false);
    expect(checkExpiry("2026-09-15", NOW)).toEqual({ ok: false, error: "The expiry date must be after today." });
    expect(checkExpiry("2026-09-14", NOW).ok).toBe(false);
    expect(checkExpiry("2026-09-16", NOW).ok).toBe(true);
    expect(checkExpiry("2027-09-15", NOW).ok).toBe(true);
    expect(checkExpiry("2027-09-16", NOW)).toEqual({
      ok: false,
      error: "The expiry date can be at most 365 days from now.",
    });
  });

  it("rejects dates that do not exist", () => {
    expect(parseLocalDate("2027-02-30")).toBeNull();
    expect(parseLocalDate("15/09/2026")).toBeNull();
    expect(checkExpiry("2027-02-30", NOW).ok).toBe(false);
  });

  it("formats local dates for date inputs", () => {
    expect(localDateString(new Date(2026, 0, 5))).toBe("2026-01-05");
  });
});

describe("validateExceptionForm", () => {
  it("reports every problem and builds no body", () => {
    const { errors, body } = validateExceptionForm(EMPTY_EXCEPTION_FORM, NOW);
    expect(body).toBeNull();
    expect(Object.keys(errors).sort()).toEqual(["expiresOn", "justification", "package"]);
  });

  it("builds the request body the server expects", () => {
    const expiresOn = localDateString(new Date(NOW + 30 * DAY_MS));
    const { errors, body } = validateExceptionForm(
      {
        ...EMPTY_EXCEPTION_FORM,
        package: "  Internal_Pkg ",
        versionSpec: " <2.0 ",
        codes: ["NETWORK_EGRESS"],
        categories: ["capability"],
        environment: "staging",
        justification: "  Build step fetches wheels from our internal mirror  ",
        expiresOn,
      },
      NOW,
    );
    expect(errors).toEqual({});
    expect(body).toEqual({
      package: "Internal_Pkg",
      version_spec: "<2.0",
      codes: ["NETWORK_EGRESS"],
      categories: ["capability"],
      environment: "staging",
      justification: "Build step fetches wheels from our internal mirror",
      expires_at: parseLocalDate(expiresOn)?.toISOString(),
    });
  });

  it("refuses an environment that differs from the selected policy's", () => {
    const { errors } = validateExceptionForm(
      { ...EMPTY_EXCEPTION_FORM, policyId: "p-1", environment: "staging" },
      NOW,
      "production",
    );
    expect(errors.environment).toMatch(/must match/);
  });
});
