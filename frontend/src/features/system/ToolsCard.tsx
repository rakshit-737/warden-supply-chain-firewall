import type { ApiError } from "../../api/client";
import { Card } from "../../components/Card";
import { DataTable, type Column } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { revealInvisible } from "../../lib/text";
import type { ToolRow } from "./systemInfo";

const COLUMNS: readonly Column<ToolRow>[] = [
  {
    id: "name",
    header: "Tool",
    sortValue: (tool) => tool.name,
    cell: (tool) => <span className="font-mono text-[0.8125rem] text-ink">{revealInvisible(tool.name)}</span>,
  },
  {
    id: "status",
    header: "Status",
    sortValue: (tool) => tool.available,
    cell: (tool) =>
      tool.available ? (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-semibold text-ink">
          <span aria-hidden="true" className="h-2 w-2 rounded-full bg-verdict-allow" />
          Available
        </span>
      ) : (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs text-ink-secondary">
          <span aria-hidden="true" className="h-2 w-2 rounded-full border border-ink-muted" />
          Not available
        </span>
      ),
  },
  {
    id: "version",
    header: "Version",
    cell: (tool) =>
      tool.version ? (
        <span className="break-all font-mono text-[0.8125rem] text-ink">{revealInvisible(tool.version)}</span>
      ) : (
        <span className="text-ink-muted">Not reported</span>
      ),
  },
  {
    id: "detail",
    header: "Detail",
    className: "min-w-48",
    cell: (tool) =>
      tool.detail ? (
        <span className="wrap-break-word text-ink-secondary">{revealInvisible(tool.detail)}</span>
      ) : (
        <span className="text-ink-muted">None</span>
      ),
  },
];

export interface ToolsCardProps {
  /** undefined until the first response arrives. */
  rows: ToolRow[] | undefined;
  loading: boolean;
  error: ApiError | null;
  onRetry: () => void;
}

/** GET /system/tools: availability of the optional external analysis tools. */
export function ToolsCard({ rows, loading, error, onRetry }: ToolsCardProps) {
  return (
    <Card
      title="Analysis tools"
      description="Optional external tools the analyzers use, as found by the API process that answered. The server caches these checks per process."
      flush
    >
      <DataTable
        caption="Analysis tools"
        columns={COLUMNS}
        rows={rows}
        rowKey={(tool) => tool.key}
        loading={loading}
        error={error}
        onRetry={onRetry}
        empty={<EmptyState compact title="This server reports no analysis tools." />}
      />
    </Card>
  );
}
