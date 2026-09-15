import { vi } from "vitest";
import type { Role, User } from "../api/types";
import type { AuthState } from "../auth/context";

export function makeUser(role: Role): User {
  return {
    id: "user-1",
    email: "analyst@example.test",
    role,
    is_active: true,
    created_at: "2026-01-01T00:00:00Z",
  };
}

/** Auth context value for tests; `null` means nobody is signed in. */
export function makeAuthState(role: Role | null, overrides: Partial<AuthState> = {}): AuthState {
  return {
    user: role ? makeUser(role) : null,
    loading: false,
    restoreError: null,
    retryRestore: vi.fn(),
    login: vi.fn(() => Promise.resolve()),
    logout: vi.fn(() => Promise.resolve()),
    ...overrides,
  };
}
