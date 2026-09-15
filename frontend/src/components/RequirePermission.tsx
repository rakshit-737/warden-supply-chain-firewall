import type { ReactNode } from "react";
import type { Permission } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { EmptyState } from "./EmptyState";
import { PageHeader } from "./PageHeader";

/** Shows `children` only to roles holding `permission`. The server enforces the same rule. */
export function RequirePermission({ permission, children }: { permission: Permission; children: ReactNode }) {
  const allowed = usePermission(permission);
  if (allowed) return <>{children}</>;
  return (
    <>
      <PageHeader title="Access restricted" />
      <EmptyState
        title="Your role cannot open this view."
        description="Ask an administrator if you need access. The server applies the same restriction to the underlying data."
      />
    </>
  );
}
