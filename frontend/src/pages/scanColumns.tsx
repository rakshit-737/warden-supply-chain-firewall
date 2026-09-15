import { Link } from "react-router";
import { DECISIONS, type ScanSummary } from "../api/types";
import type { Column } from "../components/DataTable";
import { DecisionBadge } from "../components/DecisionBadge";
import { RiskGauge } from "../components/RiskGauge";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatDateTime, humanize } from "../lib/format";
import { severityRank } from "../lib/risk";

/** Columns for lists of scan summaries (Scans page and the dashboard). */
export function scanSummaryColumns(options: { showEnvironment?: boolean } = {}): Column<ScanSummary>[] {
  const columns: Column<ScanSummary>[] = [
    {
      id: "package",
      header: "Package",
      sortValue: (scan) => `${scan.package_name}==${scan.version}`,
      cell: (scan) => (
        <Link
          to={`/scans/${encodeURIComponent(scan.id)}`}
          className="break-words font-mono text-[0.8125rem] text-ink hover:text-accent hover:underline"
        >
          {scan.package_name}
          <span className="text-ink-muted">=={scan.version}</span>
        </Link>
      ),
    },
    {
      id: "risk",
      header: "Risk",
      sortValue: (scan) => scan.risk_score,
      cell: (scan) => <RiskGauge score={scan.risk_score} size="sm" label={`Risk score of ${scan.package_name}`} />,
    },
    {
      id: "severity",
      header: "Severity",
      sortValue: (scan) => severityRank(scan.severity),
      cell: (scan) => <SeverityBadge value={scan.severity} />,
    },
    {
      id: "decision",
      header: "Decision",
      sortValue: (scan) => DECISIONS.indexOf(scan.decision),
      cell: (scan) => <DecisionBadge value={scan.decision} />,
    },
  ];
  if (options.showEnvironment) {
    columns.push({
      id: "environment",
      header: "Environment",
      sortValue: (scan) => scan.environment ?? "",
      cell: (scan) =>
        scan.environment ? humanize(scan.environment) : <span className="text-ink-muted">Not recorded</span>,
    });
  }
  columns.push({
    id: "created",
    header: "Scanned",
    sortValue: (scan) => scan.created_at,
    cell: (scan) => (
      <time dateTime={scan.created_at} className="whitespace-nowrap tabular-nums text-ink-secondary">
        {formatDateTime(scan.created_at)}
      </time>
    ),
  });
  return columns;
}
