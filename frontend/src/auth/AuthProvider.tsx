import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { login as loginRequest, logout as logoutRequest, me } from "../api/auth";
import {
  isSessionRejection,
  refreshSession,
  registerLogoutHandler,
  setAccessToken,
  toApiError,
  type ApiError,
} from "../api/client";
import type { User } from "../api/types";
import { AuthContext, type AuthState } from "./context";

/**
 * Session state. The access token lives only in memory (api/client.ts); the refresh token is an
 * httpOnly cookie the page cannot read. On load the session is restored through that cookie. Only a
 * session the server refuses leads to the sign-in form: when the check itself fails (429, 5xx,
 * timeout, network), restoreError is set instead and the check can be retried.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [restoreError, setRestoreError] = useState<ApiError | null>(null);
  const [restoreAttempt, setRestoreAttempt] = useState(0);

  useEffect(() => {
    registerLogoutHandler(() => {
      setAccessToken(null);
      setUser(null);
    });
    return () => registerLogoutHandler(null);
  }, []);

  useEffect(() => {
    let active = true;
    // refreshSession() shares one in-flight request, so running this effect twice (StrictMode)
    // cannot trip the server's refresh-token reuse detection.
    void refreshSession()
      .then(async (token) => {
        if (token === null || !active) return null;
        try {
          return await me();
        } catch (err) {
          if (!isSessionRejection(err)) throw err;
          setAccessToken(null);
          return null;
        }
      })
      .then(
        (restored) => {
          if (!active) return;
          setUser(restored);
          setRestoreError(null);
        },
        (err: unknown) => {
          if (!active) return;
          setUser(null);
          setRestoreError(toApiError(err));
        },
      )
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [restoreAttempt]);

  const retryRestore = useCallback(() => {
    setLoading(true);
    setRestoreError(null);
    setRestoreAttempt((attempt) => attempt + 1);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const tokens = await loginRequest(email, password);
    setAccessToken(tokens.access_token);
    setUser(await me());
    setRestoreError(null);
  }, []);

  const logout = useCallback(async () => {
    try {
      await logoutRequest();
    } catch {
      // The local session is cleared either way; the server-side token expires on its own.
    } finally {
      setAccessToken(null);
      setUser(null);
    }
  }, []);

  const value = useMemo<AuthState>(
    () => ({ user, loading, restoreError, retryRestore, login, logout }),
    [user, loading, restoreError, retryRestore, login, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
