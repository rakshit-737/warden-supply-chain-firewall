import { describe, expect, it } from "vitest";
import { USER_ROLES, type UserRole } from "../api/types";
import { PERMISSIONS, hasPermission, normalizeRole, permissionsFor, type Permission } from "./permissions";

const ENGINEERING: UserRole[] = ["admin", "security_analyst", "developer"];
const EVERYONE: UserRole[] = [...USER_ROLES];

// SPEC section 6, transcribed row by row.
const MATRIX: Record<Permission, UserRole[]> = {
  "scan:create": ENGINEERING,
  "project:write": ENGINEERING,
  "container:scan": ENGINEERING,
  "diff:create": ENGINEERING,
  "scan:read": EVERYONE,
  "project:read": EVERYONE,
  "event:read": EVERYONE,
  "monitor:read": EVERYONE,
  "policy:read": EVERYONE,
  "report:read": EVERYONE,
  "ml:read": EVERYONE,
  "vuln:read": EVERYONE,
  "exception:request": ENGINEERING,
  "exception:approve": ["admin", "security_analyst"],
  "event:ack": ["admin", "security_analyst"],
  "monitor:write": ["admin", "security_analyst"],
  "policy:write": ["admin"],
  "user:manage": ["admin"],
  "system:write": ["admin"],
  "audit:read": ["admin", "auditor"],
  "system:read": ["admin", "auditor"],
};

describe("role permissions mirror SPEC section 6", () => {
  it("covers exactly the permissions in the spec", () => {
    expect(Object.keys(MATRIX).sort()).toEqual(Object.values(PERMISSIONS).sort());
  });

  for (const [permission, roles] of Object.entries(MATRIX) as [Permission, UserRole[]][]) {
    it(`grants ${permission} to ${roles.join(", ")} only`, () => {
      for (const role of USER_ROLES) {
        expect(hasPermission(role, permission), `${role} / ${permission}`).toBe(roles.includes(role));
      }
    });
  }
});

describe("role handling", () => {
  it("maps v1 role names to their current equivalents", () => {
    expect(normalizeRole("analyst")).toBe("security_analyst");
    expect(normalizeRole(" Viewer ")).toBe("read_only");
    expect(hasPermission("viewer", PERMISSIONS.SCAN_CREATE)).toBe(false);
    expect(hasPermission("analyst", PERMISSIONS.EXCEPTION_APPROVE)).toBe(true);
  });

  it("denies unknown or missing roles everything", () => {
    expect(permissionsFor("superuser").size).toBe(0);
    expect(hasPermission(undefined, PERMISSIONS.SCAN_READ)).toBe(false);
    expect(hasPermission("__proto__", PERMISSIONS.SCAN_READ)).toBe(false);
  });

  it("requires every listed permission and never allows an empty list", () => {
    expect(hasPermission("admin")).toBe(false);
    expect(hasPermission("developer", PERMISSIONS.SCAN_CREATE, PERMISSIONS.EXCEPTION_APPROVE)).toBe(false);
    expect(hasPermission("security_analyst", PERMISSIONS.SCAN_CREATE, PERMISSIONS.EXCEPTION_APPROVE)).toBe(true);
  });
});
