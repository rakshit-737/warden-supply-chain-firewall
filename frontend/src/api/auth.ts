import { api, type RequestOptions } from "./client";
import type { TokenResponse, User } from "./types";

export async function login(email: string, password: string): Promise<TokenResponse> {
  const r = await api.post<TokenResponse>("/auth/login", { email, password });
  return r.data;
}

/** Rotates the httpOnly refresh cookie and returns a new access token. */
export async function refresh(): Promise<TokenResponse> {
  const r = await api.post<TokenResponse>("/auth/refresh");
  return r.data;
}

export async function logout(): Promise<void> {
  await api.post("/auth/logout");
}

export async function me(opts: RequestOptions = {}): Promise<User> {
  const r = await api.get<User>("/auth/me", { signal: opts.signal });
  return r.data;
}
