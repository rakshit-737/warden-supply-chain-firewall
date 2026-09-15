import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { isAbortError, toApiError, type ApiError } from "../api/client";

interface Settled<T> {
  key: string;
  nonce: number;
  data: T | undefined;
  error: ApiError | null;
}

export interface ApiQuery<T> {
  /** Data for the current key. Kept on screen while the same key reloads. */
  data: T | undefined;
  /** Last successful data for any key, so a table can hold its rows while the next page loads. */
  previousData: T | undefined;
  error: ApiError | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Load data for `key` (pass null to skip). A new key or a reload aborts the in-flight request.
 * The fetcher may close over props; the latest fetcher is used whenever a request starts.
 *
 * Loading state is derived from which key last settled rather than set inside the effect, so no
 * state update ever happens synchronously during an effect.
 */
export function useApiQuery<T>(key: string | null, fetcher: (signal: AbortSignal) => Promise<T>): ApiQuery<T> {
  const fetcherRef = useRef(fetcher);
  useLayoutEffect(() => {
    fetcherRef.current = fetcher;
  });
  const [nonce, setNonce] = useState(0);
  const [settled, setSettled] = useState<Settled<T> | null>(null);

  useEffect(() => {
    if (key === null) return;
    const controller = new AbortController();
    fetcherRef.current(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setSettled({ key, nonce, data, error: null });
      },
      (err: unknown) => {
        if (controller.signal.aborted || isAbortError(err)) return;
        setSettled((prev) => ({
          key,
          nonce,
          data: prev?.key === key ? prev.data : undefined,
          error: toApiError(err),
        }));
      },
    );
    return () => controller.abort();
  }, [key, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const sameKey = settled !== null && settled.key === key;
  const current = sameKey && settled.nonce === nonce;
  return {
    data: sameKey ? settled.data : undefined,
    previousData: settled?.data,
    error: current ? settled.error : null,
    loading: key !== null && !current,
    reload,
  };
}
