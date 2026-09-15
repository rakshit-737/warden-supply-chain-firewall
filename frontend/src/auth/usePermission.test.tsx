import { renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";
import type { Role } from "../api/types";
import { makeAuthState } from "../test/auth";
import { AuthContext } from "./context";
import { PERMISSIONS } from "./permissions";
import { usePermission } from "./usePermission";

function wrapperFor(role: Role | null) {
  const auth = makeAuthState(role);
  return function Wrapper({ children }: { children: ReactNode }) {
    return <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>;
  };
}

describe("usePermission", () => {
  it("follows the signed-in user's role", () => {
    const analyst = renderHook(() => usePermission(PERMISSIONS.EXCEPTION_APPROVE), { wrapper: wrapperFor("security_analyst") });
    expect(analyst.result.current).toBe(true);
    const developer = renderHook(() => usePermission(PERMISSIONS.EXCEPTION_APPROVE), { wrapper: wrapperFor("developer") });
    expect(developer.result.current).toBe(false);
  });

  it("grants nothing when nobody is signed in", () => {
    const { result } = renderHook(() => usePermission(PERMISSIONS.SCAN_READ), { wrapper: wrapperFor(null) });
    expect(result.current).toBe(false);
  });
});
