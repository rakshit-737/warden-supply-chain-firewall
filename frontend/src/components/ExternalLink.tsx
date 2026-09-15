import type { ReactNode } from "react";
import { safeHttpUrl } from "../lib/url";

export interface ExternalLinkProps {
  /** Untrusted URL. Only absolute http(s) URLs without credentials become links. */
  href: unknown;
  children?: ReactNode;
  className?: string;
  /** Drop the default link colour and underline (for chips that style themselves). */
  plain?: boolean;
}

/**
 * Link to an external site in a new tab, without referrer or opener. Any other scheme
 * (javascript:, data:, file:, relative paths) is shown as inert text instead of a link.
 */
export function ExternalLink({ href, children, className = "", plain = false }: ExternalLinkProps) {
  const url = safeHttpUrl(href);
  const content = children ?? (typeof href === "string" ? href : "");
  if (url === null) {
    return <span className={`break-all text-ink-secondary ${className}`}>{content}</span>;
  }
  const look = plain ? "" : "text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent";
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className={`break-all ${look} ${className}`}
    >
      {content}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}
