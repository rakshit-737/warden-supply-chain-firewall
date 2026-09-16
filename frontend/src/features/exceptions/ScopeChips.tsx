import { humanize } from "../../lib/format";
import { stringArray } from "../../lib/values";

export interface ScopeChipsProps {
  codes: unknown;
  categories: unknown;
  /** Show at most this many chips, then "+N more". Omit to show all. */
  limit?: number;
  emptyText?: string;
}

/** Categories (humanised) and finding codes (monospace) an exception is scoped to, as plain text chips. */
export function ScopeChips({ codes, categories, limit, emptyText = "No codes or categories" }: ScopeChipsProps) {
  const items = [
    ...stringArray(categories).map((category) => ({ key: `category:${category}`, label: humanize(category), mono: false })),
    ...stringArray(codes).map((code) => ({ key: `code:${code}`, label: code, mono: true })),
  ];
  if (items.length === 0) return <span className="text-ink-muted">{emptyText}</span>;
  const shown = limit === undefined ? items : items.slice(0, limit);
  const rest = items.length - shown.length;
  return (
    <span className="flex flex-wrap items-center gap-1">
      {shown.map((item) => (
        <span
          key={item.key}
          className={`break-all rounded bg-raised px-1.5 py-0.5 text-2xs text-ink ${item.mono ? "font-mono" : ""}`}
        >
          {item.label}
        </span>
      ))}
      {rest > 0 && <span className="whitespace-nowrap text-2xs text-ink-muted">+{rest} more</span>}
    </span>
  );
}
