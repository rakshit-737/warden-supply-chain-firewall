import { useId, type ReactNode } from "react";

export interface CardProps {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  /** Remove body padding (for edge-to-edge tables and lists). */
  flush?: boolean;
  className?: string;
}

/** A titled panel. With a title it is a labelled region, so it appears in landmark navigation. */
export function Card({ title, description, actions, children, flush = false, className = "" }: CardProps) {
  const headingId = useId();
  const hasTitle = title !== undefined && title !== null;
  return (
    <section
      aria-labelledby={hasTitle ? headingId : undefined}
      className={`min-w-0 rounded-md border border-line bg-panel ${className}`}
    >
      {(hasTitle || actions) && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2.5">
          <div className="min-w-0">
            {hasTitle && (
              <h2 id={headingId} className="text-[0.9375rem] font-semibold text-ink">
                {title}
              </h2>
            )}
            {description && <p className="text-xs text-ink-secondary">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={flush ? "" : "p-4"}>{children}</div>
    </section>
  );
}
