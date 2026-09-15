import { useState, type ReactNode } from "react";
import type { ApiError } from "../api/client";
import { formatCount } from "../lib/format";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { LoadingBlock } from "./Skeleton";

export type SortDirection = "asc" | "desc";
export type SortValue = string | number | boolean | null | undefined;

export interface SortState {
  columnId: string;
  direction: SortDirection;
}

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Value used for sorting on this page. Supplying it makes the column sortable. */
  sortValue?: (row: T) => SortValue;
  /** Mark a column sortable in controlled (server-side) mode without a sortValue. */
  sortable?: boolean;
  align?: "left" | "right";
  className?: string;
}

export interface Pagination {
  total: number;
  limit: number;
  offset: number;
  onOffsetChange: (offset: number) => void;
}

export interface DataTableProps<T> {
  /** Accessible table name; visible when `showCaption` is set. */
  caption: string;
  showCaption?: boolean;
  columns: readonly Column<T>[];
  /** undefined while the first page is loading. */
  rows: readonly T[] | undefined;
  rowKey: (row: T) => string;
  /** True while rows are being (re)loaded. Existing rows stay visible, dimmed. */
  loading?: boolean;
  error?: ApiError | string | null;
  onRetry?: () => void;
  empty?: ReactNode;
  /** Controlled sort (for example performed by the server). Rows are then rendered in the given order. */
  sort?: SortState | null;
  onSortChange?: (sort: SortState | null) => void;
  defaultSort?: SortState | null;
  pagination?: Pagination;
  footnote?: ReactNode;
}

function isBlank(value: SortValue): boolean {
  return value === null || value === undefined || value === "";
}

function compareValues(a: SortValue, b: SortValue): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
}

function SortGlyph({ direction }: { direction: SortDirection | null }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 8 12" className="h-3 w-2">
      <path d="M4 1 7 5H1Z" className={direction === "asc" ? "fill-ink" : "fill-line-strong"} />
      <path d="M4 11 1 7h6Z" className={direction === "desc" ? "fill-ink" : "fill-line-strong"} />
    </svg>
  );
}

function PaginationControls({ total, limit, offset, onOffsetChange }: Pagination) {
  const size = Math.max(1, limit);
  const first = total === 0 ? 0 : Math.min(offset + 1, total);
  const last = Math.min(offset + size, total);
  return (
    <nav aria-label="Pagination" className="flex items-center gap-2">
      <span aria-live="polite" className="tabular-nums">
        {formatCount(first)}–{formatCount(last)} of {formatCount(total)}
      </span>
      <button
        type="button"
        className="btn-secondary h-7 px-2"
        disabled={offset <= 0}
        onClick={() => onOffsetChange(Math.max(0, offset - size))}
      >
        Previous
      </button>
      <button
        type="button"
        className="btn-secondary h-7 px-2"
        disabled={offset + size >= total}
        onClick={() => onOffsetChange(offset + size)}
      >
        Next
      </button>
    </nav>
  );
}

/**
 * Typed table with sortable headers, server pagination controls and loading, empty and error
 * states. Without `onSortChange`, sorting reorders the rows it was given (the current page).
 */
export function DataTable<T>({
  caption,
  showCaption = false,
  columns,
  rows,
  rowKey,
  loading = false,
  error = null,
  onRetry,
  empty,
  sort,
  onSortChange,
  defaultSort = null,
  pagination,
  footnote,
}: DataTableProps<T>) {
  const [internalSort, setInternalSort] = useState<SortState | null>(defaultSort);
  const controlled = onSortChange !== undefined;
  const activeSort = controlled ? (sort ?? null) : internalSort;

  function toggleSort(columnId: string) {
    const next: SortState | null =
      activeSort?.columnId !== columnId
        ? { columnId, direction: "asc" }
        : activeSort.direction === "asc"
          ? { columnId, direction: "desc" }
          : null;
    if (onSortChange) onSortChange(next);
    else setInternalSort(next);
  }

  const sortColumn = activeSort ? columns.find((column) => column.id === activeSort.columnId) : undefined;
  const getter = sortColumn?.sortValue;
  const displayRows =
    !controlled && rows && activeSort && getter
      ? rows
          .map((row, index) => ({ row, index, value: getter(row) }))
          .sort((a, b) => {
            const aBlank = isBlank(a.value);
            const bBlank = isBlank(b.value);
            if (aBlank || bBlank) return aBlank === bBlank ? a.index - b.index : aBlank ? 1 : -1;
            const order = compareValues(a.value, b.value) * (activeSort.direction === "asc" ? 1 : -1);
            return order || a.index - b.index;
          })
          .map((entry) => entry.row)
      : rows;

  let body: ReactNode;
  if (error && !displayRows) {
    body = (
      <div className="p-4">
        <ErrorState error={error} onRetry={onRetry} />
      </div>
    );
  } else if (!displayRows || (displayRows.length === 0 && loading)) {
    body = (
      <div className="px-4">
        <LoadingBlock label={`Loading ${caption.toLowerCase()}`} rows={5} />
      </div>
    );
  } else if (displayRows.length === 0) {
    body = <div className="px-4">{empty ?? <EmptyState compact title="Nothing to show." />}</div>;
  } else {
    body = (
      <div className="overflow-x-auto">
        <table
          aria-busy={loading || undefined}
          className={`w-full border-collapse text-left text-[0.8125rem] transition-opacity ${loading ? "opacity-60" : ""}`}
        >
          <caption className={showCaption ? "px-4 py-2 text-left text-xs text-ink-secondary" : "sr-only"}>{caption}</caption>
          <thead>
            <tr className="border-b border-line">
              {columns.map((column) => {
                const sortable = column.sortable ?? column.sortValue !== undefined;
                const direction = activeSort?.columnId === column.id ? activeSort.direction : null;
                return (
                  <th
                    key={column.id}
                    scope="col"
                    aria-sort={
                      direction === "asc" ? "ascending" : direction === "desc" ? "descending" : sortable ? "none" : undefined
                    }
                    className={`whitespace-nowrap px-3 py-2 text-xs font-medium text-ink-secondary first:pl-4 last:pr-4 ${
                      column.align === "right" ? "text-right" : ""
                    }`}
                  >
                    {sortable ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(column.id)}
                        className="inline-flex items-center gap-1 hover:text-ink"
                      >
                        {column.header}
                        <SortGlyph direction={direction} />
                      </button>
                    ) : (
                      column.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {displayRows.map((row) => (
              <tr key={rowKey(row)} className="border-b border-line/60 last:border-0 hover:bg-raised/40">
                {columns.map((column) => (
                  <td
                    key={column.id}
                    className={`px-3 py-2 align-middle first:pl-4 last:pr-4 ${
                      column.align === "right" ? "text-right tabular-nums" : ""
                    } ${column.className ?? ""}`}
                  >
                    {column.cell(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="min-w-0">
      {error && displayRows && (
        <div className="p-3">
          <ErrorState error={error} onRetry={onRetry} title="Refreshing failed. Showing the last rows that loaded." />
        </div>
      )}
      {body}
      {(pagination || footnote) && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-2 text-xs text-ink-secondary">
          <div className="min-w-0">{footnote}</div>
          {pagination && <PaginationControls {...pagination} />}
        </div>
      )}
    </div>
  );
}
