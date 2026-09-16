import axios from "axios";
import { api, cleanParams, pathSegment, refreshSession, type RequestOptions } from "./client";
import type { ListUsersParams, Page, User, UserRegistration, UserUpdate } from "./types";

/** `ApiError.code` of the 409 returned when a change would leave the deployment without an active admin. */
export const LAST_ADMIN_ERROR_CODE = "last_admin";

/** Password length bounds of POST /auth/register, in Unicode code points (the server counts with Python len). */
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;

/** Longest email search GET /users accepts. */
export const USER_SEARCH_MAX_LENGTH = 320;

/** Requires user:manage. */
export async function listUsers(params: ListUsersParams = {}, opts: RequestOptions = {}): Promise<Page<User>> {
  const r = await api.get<Page<User>>("/users", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

/** Requires user:manage. Fails with 409 `last_admin` when the change would leave no active admin. */
export async function updateUser(id: string, patch: UserUpdate): Promise<User> {
  const r = await api.patch<User>(`/users/${pathSegment(id)}`, patch);
  return r.data;
}

/**
 * Requires user:manage. Creates an account through POST /auth/register; 409 when the email is taken.
 *
 * The client's automatic session refresh skips /auth/ paths so a failing sign-in or refresh cannot
 * loop, which would turn an expired access token into a spurious failure here. This call therefore
 * refreshes once itself and retries. The server rejects an unauthenticated request before it creates
 * anything, so the retry cannot register the account twice.
 */
export async function registerUser(body: UserRegistration): Promise<User> {
  try {
    const r = await api.post<User>("/auth/register", body);
    return r.data;
  } catch (err) {
    if (!axios.isAxiosError(err) || err.response?.status !== 401) throw err;
    const token = await refreshSession();
    if (token === null) throw err;
    const r = await api.post<User>("/auth/register", body);
    return r.data;
  }
}
