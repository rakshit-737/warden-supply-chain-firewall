import { useEffect, useState } from "react";

/**
 * The current time in epoch milliseconds, updated every `intervalMs`, so relative timestamps
 * ("2 minutes ago") stay current. Use one per page rather than one per row.
 */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}
