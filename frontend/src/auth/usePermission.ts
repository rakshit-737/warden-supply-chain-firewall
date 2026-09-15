import { hasPermission, type Permission } from "./permissions";
import { useAuth } from "./useAuth";

/**
 * Whether the signed-in user's role holds every listed permission.
 *
 * UI affordance only: use it to hide or disable controls a role cannot use. The server enforces
 * RBAC on every request, so this is never the security boundary.
 */
export function usePermission(...permissions: Permission[]): boolean {
  const { user } = useAuth();
  return hasPermission(user?.role, ...permissions);
}
