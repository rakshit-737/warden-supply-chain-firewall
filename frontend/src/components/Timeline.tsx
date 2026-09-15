import type { ReactNode } from "react";
import type { Severity } from "../api/types";
import { formatDateTime } from "../lib/format";
import { SEVERITY_FILL } from "../theme/classes";

export interface TimelineItem {
  id: string;
  title: ReactNode;
  /** ISO timestamp. */
  time?: string | null;
  description?: ReactNode;
  /** Colours the marker. Always state the severity in the text as well. */
  tone?: Severity;
}

export interface TimelineProps {
  items: TimelineItem[];
  label?: string;
}

/** Chronological list (callers pass items in the order to display, usually newest first). */
export function Timeline({ items, label }: TimelineProps) {
  return (
    <ol aria-label={label} className="min-w-0">
      {items.map((item, index) => (
        <li key={item.id} className="grid grid-cols-[0.75rem_minmax(0,1fr)] gap-x-3">
          <span aria-hidden="true" className="relative flex justify-center">
            {index < items.length - 1 && <span className="absolute bottom-0 top-4 w-px bg-line" />}
            <span
              className={`relative mt-[0.4rem] h-2 w-2 rounded-full ${item.tone ? SEVERITY_FILL[item.tone] : "bg-ink-muted"}`}
            />
          </span>
          <div className={`min-w-0 ${index < items.length - 1 ? "pb-3" : ""}`}>
            <div className="flex flex-wrap items-baseline justify-between gap-x-3">
              <span className="min-w-0 break-words font-medium text-ink">{item.title}</span>
              {item.time && (
                <time dateTime={item.time} className="text-xs tabular-nums text-ink-muted">
                  {formatDateTime(item.time)}
                </time>
              )}
            </div>
            {item.description && <div className="mt-0.5 min-w-0 break-words text-ink-secondary">{item.description}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}
