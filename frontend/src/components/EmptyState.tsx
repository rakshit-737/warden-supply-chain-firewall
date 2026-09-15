import type { ReactNode } from "react";

export interface EmptyStateProps {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  /** Inline variant for use inside tables and tabs. */
  compact?: boolean;
}

export function EmptyState({ title, description, action, compact = false }: EmptyStateProps) {
  return (
    <div
      className={`flex flex-col items-start gap-1 ${compact ? "py-3" : "rounded-md border border-line bg-sunken px-5 py-6"}`}
    >
      <p className="font-medium text-ink">{title}</p>
      {description && <div className="max-w-prose text-ink-secondary">{description}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
