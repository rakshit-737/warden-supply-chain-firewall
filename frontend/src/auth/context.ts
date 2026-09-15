import { createContext } from "react";
import type { ApiError } from "../api/client";
import type { User } from "../api/types";

export interface AuthState {
  user: User | null;
  /** True while the session is being restored: on load, and again after retryRestore(). */
  loading: boolean;
  /**
   * Set when the session could not be checked (rate limited, server error, timeout, network failure).
   * The user is then neither signed in nor known to be signed out, so the sign-in form is not shown;
   * retryRestore() checks again.
   */
  restoreError: ApiError | null;
  retryRestore: () => void;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | undefined>(undefined);
