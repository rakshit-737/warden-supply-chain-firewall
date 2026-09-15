import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { ListUsersParams, Page, User, UserUpdate } from "./types";

/** Requires user:manage. */
export async function listUsers(params: ListUsersParams = {}, opts: RequestOptions = {}): Promise<Page<User>> {
  const r = await api.get<Page<User>>("/users", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

/** Requires user:manage. */
export async function updateUser(id: string, patch: UserUpdate): Promise<User> {
  const r = await api.patch<User>(`/users/${pathSegment(id)}`, patch);
  return r.data;
}
