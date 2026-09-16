import { useId } from "react";
import { formatRelativeTime } from "./time";

export interface AutoRefreshControlProps {
  enabled: boolean;
  onToggle: (enabled: boolean) => void;
  /** Polling is paused because the tab is hidden. */
  hidden: boolean;
  intervalSeconds: number;
  /** When the data on screen was fetched (epoch ms). */
  lastUpdatedAt?: number;
  now: number;
  refreshing: boolean;
  onRefresh: () => void;
}

export function AutoRefreshControl({
  enabled,
  onToggle,
  hidden,
  intervalSeconds,
  lastUpdatedAt,
  now,
  refreshing,
  onRefresh,
}: AutoRefreshControlProps) {
  const id = useId();
  const mode = !enabled ? "Off" : hidden ? "Paused while this tab is hidden" : `Every ${intervalSeconds} seconds`;
  const updated =
    lastUpdatedAt === undefined ? null : formatRelativeTime(new Date(lastUpdatedAt).toISOString(), Math.max(now, lastUpdatedAt));
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div className="flex flex-col">
        <label className="inline-flex items-center gap-2 text-[0.8125rem] font-medium text-ink">
          <input
            type="checkbox"
            role="switch"
            className="h-4 w-4 accent-accent"
            checked={enabled}
            aria-describedby={`${id}-mode`}
            onChange={(event) => onToggle(event.target.checked)}
          />
          Auto-refresh
        </label>
        <span id={`${id}-mode`} className="text-xs text-ink-muted">
          {mode}
          {updated ? `, updated ${updated}` : ""}
        </span>
      </div>
      <button
        type="button"
        className="btn-secondary"
        aria-disabled={refreshing || undefined}
        onClick={() => {
          if (!refreshing) onRefresh();
        }}
      >
        {refreshing ? "Refreshing" : "Refresh"}
      </button>
    </div>
  );
}
