import { useEffect, type ReactNode } from "react";
import { Link } from "react-router";

export interface PageHeaderProps {
  /** Plain-text page title; also used for the browser tab title. */
  title: string;
  /** Rich replacement for the visible heading (e.g. package name in monospace). */
  heading?: ReactNode;
  description?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
  back?: { to: string; label: string };
}

export function PageHeader({ title, heading, description, meta, actions, back }: PageHeaderProps) {
  useEffect(() => {
    document.title = `${title} | Warden X`;
  }, [title]);

  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-x-6 gap-y-3 border-b border-line pb-4">
      <div className="min-w-0">
        {back && (
          <Link to={back.to} className="mb-1 inline-block text-xs text-ink-secondary hover:text-ink">
            {back.label}
          </Link>
        )}
        <h1 className="wrap-break-word font-condensed text-2xl font-semibold leading-tight text-ink">{heading ?? title}</h1>
        {description && <p className="mt-1 max-w-3xl text-ink-secondary">{description}</p>}
        {meta && <div className="mt-2">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}
