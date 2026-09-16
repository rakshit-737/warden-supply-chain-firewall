import { useEffect, useState } from "react";

/** The current time in milliseconds, for event handlers that must validate against the real clock. */
export function currentTime(): number {
  return Date.now();
}

/** The current time in milliseconds, refreshed every `intervalMs`, for countdowns and expiry checks. */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(currentTime);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(currentTime()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}
