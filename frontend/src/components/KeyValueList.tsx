import type { ReactNode } from "react";

export interface KeyValueItem {
  term: ReactNode;
  /** null, undefined and "" render as `emptyText`; booleans render as Yes/No. */
  value: ReactNode;
  mono?: boolean;
  key?: string;
}

export interface KeyValueListProps {
  items: KeyValueItem[];
  columns?: 1 | 2;
  emptyText?: string;
}

export function KeyValueList({ items, columns = 1, emptyText = "Not recorded" }: KeyValueListProps) {
  return (
    <dl className={`grid gap-x-8 gap-y-1.5 ${columns === 2 ? "md:grid-cols-2" : ""}`}>
      {items.map((item, index) => {
        const missing = item.value === null || item.value === undefined || item.value === "";
        const shown = typeof item.value === "boolean" ? (item.value ? "Yes" : "No") : item.value;
        return (
          <div key={item.key ?? index} className="grid min-w-0 grid-cols-[minmax(7rem,38%)_minmax(0,1fr)] gap-3">
            <dt className="text-ink-secondary">{item.term}</dt>
            <dd
              className={`min-w-0 break-words ${
                missing ? "text-ink-muted" : item.mono ? "font-mono text-[0.8125rem] text-ink" : "text-ink"
              }`}
            >
              {missing ? emptyText : shown}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}
