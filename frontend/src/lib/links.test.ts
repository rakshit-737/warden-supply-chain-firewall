import { describe, expect, it } from "vitest";
import { SCRIPT_URL } from "../test/hostile";
import { safeFileName } from "./download";
import { findingAnchorId, formatLocation } from "./findings";
import { attackTechniqueUrl, cweUrl, safeHttpUrl } from "./url";

describe("safeHttpUrl", () => {
  it("accepts absolute http and https URLs", () => {
    expect(safeHttpUrl("https://osv.dev/vulnerability/PYSEC-2024-1")).toBe("https://osv.dev/vulnerability/PYSEC-2024-1");
    expect(safeHttpUrl(" http://example.test/a ")).toBe("http://example.test/a");
  });

  it.each([SCRIPT_URL, SCRIPT_URL.toUpperCase(),"data:text/html,<b>x</b>", "file:///etc/passwd", "/relative", "https://user:secret@example.test/", 42, null])(
    "rejects %s",
    (value) => {
      expect(safeHttpUrl(value)).toBeNull();
    },
  );
});

describe("taxonomy links", () => {
  it("builds MITRE URLs only from well-formed ids", () => {
    expect(cweUrl("CWE-94")).toBe("https://cwe.mitre.org/data/definitions/94.html");
    expect(cweUrl("CWE-94/../../x")).toBeNull();
    expect(attackTechniqueUrl("T1195")).toBe("https://attack.mitre.org/techniques/T1195/");
    expect(attackTechniqueUrl("T1195.002")).toBe("https://attack.mitre.org/techniques/T1195/002/");
    expect(attackTechniqueUrl("T11950")).toBeNull();
  });
});

describe("findings helpers", () => {
  it("formats a location without inventing a line", () => {
    expect(formatLocation({ file: "pkg/setup.py", line: 12 })).toBe("pkg/setup.py:12");
    expect(formatLocation({ file: "pkg/setup.py", line: null })).toBe("pkg/setup.py");
    expect(formatLocation({ file: "pkg/setup.py", line: 0 })).toBe("pkg/setup.py");
    expect(formatLocation({ file: "pkg/setup.py", line: 2.5 })).toBe("pkg/setup.py");
    expect(formatLocation({ file: null, line: 3 })).toBeNull();
    expect(formatLocation(undefined)).toBeNull();
  });

  it("builds anchor ids from safe characters only", () => {
    expect(findingAnchorId("abc 123/../")).toBe("finding-abc-123----");
  });
});

describe("safeFileName", () => {
  it("strips path components and unsafe characters", () => {
    expect(safeFileName("warden-reqeusts-1.0.0-report", "json")).toBe("warden-reqeusts-1.0.0-report.json");
    expect(safeFileName("../../etc/passwd", "sh;rm")).toBe("etc_passwd.shrm");
    expect(safeFileName("...", "")).toBe("warden-export.txt");
  });
});
