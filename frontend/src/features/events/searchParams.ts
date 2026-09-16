import { useCallback, useEffect } from "react";
import { useSearchParams } from "react-router";
import type { Page } from "../../api/types";

/** Query-string changes: null or "" removes the parameter. */
export type ParamChanges = Record<string, string | null>;

/** The current search params plus a stable function that merges changes into them (history replace). */
export function useSearchParamUpdater(): readonly [URLSearchParams, (changes: ParamChanges) => void] {
  const [searchParams, setSearchParams] = useSearchParams();
  const update = useCallback(
    (changes: ParamChanges) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [name, value] of Object.entries(changes)) {
            if (value === null || value === "") next.delete(name);
            else next.set(name, value);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );
  return [searchParams, update] as const;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Canonical hyphenated UUID (the form the API returns). */
export function isUuid(value: string): boolean {
  return UUID_RE.test(value.trim());
}

/**
 * A page offset from the query string: 0 when absent, null when present but not a whole number
 * from 0 to `max`.
 */
export function parseOffset(value: string | null, max = Number.MAX_SAFE_INTEGER): number | null {
  if (value === null || value.trim() === "") return 0;
  if (!/^\d{1,16}$/.test(value.trim())) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) && n <= max ? n : null;
}

/**
 * An offset past the last item (an old bookmark, or records removed since) returns no rows although
 * records exist. Moves to the last page instead of claiming the list is empty; returns whether the
 * current page is past the end.
 */
export function usePastEndRedirect(
  page: Page<unknown> | undefined,
  offset: number,
  pageSize: number,
  updateParams: (changes: ParamChanges) => void,
): boolean {
  const pastEnd = page !== undefined && page.total > 0 && page.items.length === 0 && offset > 0;
  const size = page && page.limit > 0 ? page.limit : pageSize;
  const lastPage = page ? Math.floor(Math.max(page.total - 1, 0) / size) * size : 0;
  useEffect(() => {
    if (!pastEnd || lastPage === offset) return;
    updateParams({ offset: lastPage > 0 ? String(lastPage) : null });
  }, [pastEnd, lastPage, offset, updateParams]);
  return pastEnd;
}
