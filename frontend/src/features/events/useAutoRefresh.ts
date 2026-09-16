import { useEffect, useLayoutEffect, useRef, useState } from "react";

export interface AutoRefreshOptions {
  enabled: boolean;
  intervalMs: number;
  /** Starts a refresh (for example useApiQuery's reload). */
  onRefresh: () => void;
  /** When the data on screen was fetched (epoch ms); the next refresh is due `intervalMs` after it. */
  lastUpdatedAt?: number;
  /** True while a request is in flight. A due refresh is skipped rather than aborting a slow request. */
  busy?: boolean;
}

function documentHidden(): boolean {
  return typeof document !== "undefined" && document.visibilityState === "hidden";
}

/**
 * Polls while enabled and the tab is visible. Hiding the tab pauses polling; showing it again
 * refreshes at once when a refresh became due meanwhile, then continues on the interval.
 * Returns whether polling is currently paused because the tab is hidden.
 */
export function useAutoRefresh({ enabled, intervalMs, onRefresh, lastUpdatedAt, busy = false }: AutoRefreshOptions): {
  hidden: boolean;
} {
  const latest = useRef({ onRefresh, busy });
  useLayoutEffect(() => {
    latest.current = { onRefresh, busy };
  });

  const [hidden, setHidden] = useState(documentHidden);
  useEffect(() => {
    const onVisibilityChange = () => setHidden(documentHidden());
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, []);

  useEffect(() => {
    if (!enabled || hidden) return;
    const current = latest;
    let timer: number | undefined;
    const tick = () => {
      if (!current.current.busy) current.current.onRefresh();
      timer = window.setTimeout(tick, intervalMs);
    };
    const age = lastUpdatedAt === undefined ? 0 : Math.max(0, Date.now() - lastUpdatedAt);
    timer = window.setTimeout(tick, Math.max(0, intervalMs - age));
    return () => window.clearTimeout(timer);
  }, [enabled, hidden, intervalMs, lastUpdatedAt]);

  return { hidden };
}
