import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { api, registerLogoutHandler, setAccessToken } from "../api/client";
import type { User } from "../api/types";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthCtx = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function loadMe() {
    try {
      const me = await api.get<User>("/auth/me");
      setUser(me.data);
    } catch {
      setUser(null);
    }
  }

  useEffect(() => {
    registerLogoutHandler(() => setUser(null));
    // Attempt a silent session restore via the refresh cookie on first load.
    (async () => {
      try {
        const resp = await api.post("/auth/refresh");
        setAccessToken(resp.data.access_token);
        await loadMe();
      } catch {
        setUser(null);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  async function login(email: string, password: string) {
    const resp = await api.post("/auth/login", { email, password });
    setAccessToken(resp.data.access_token);
    await loadMe();
  }

  async function logout() {
    try {
      await api.post("/auth/logout");
    } finally {
      setAccessToken(null);
      setUser(null);
    }
  }

  const value = useMemo(() => ({ user, loading, login, logout }), [user, loading]);
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
