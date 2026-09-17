import { useState } from "react";
import { Link } from "react-router";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Tooltip as ChartTooltip,
  LabelList,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from "recharts";
import { listEvents } from "../api/events";
import { getScanStats, listScans } from "../api/scans";
import { DECISIONS, SEVERITIES, type ScanStats, type SecurityEvent } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DecisionBadge } from "../components/DecisionBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { SeverityBadge } from "../components/SeverityBadge";
import { LoadingBlock } from "../components/Skeleton";
import { StatTile } from "../components/StatTile";
import { Timeline } from "../components/Timeline";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatCount, formatPercent, humanize } from "../lib/format";
import { SEVERITY_LABEL, isSeverity, severityForScore } from "../lib/risk";
import { numberOrNull } from "../lib/values";
import { DECISION_FILL } from "../theme/classes";
import { palette } from "../theme/palette";
import { scanSummaryColumns } from "./scanColumns";

const RECENT_SCAN_COLUMNS = scanSummaryColumns();

function countOf(record: Partial<Record<string, number>> | null | undefined, key: string): number {
  return numberOrNull(record?.[key]) ?? 0;
}

function VerdictsCard({ stats }: { stats: ScanStats }) {
  const counts = DECISIONS.map((decision) => ({ decision, count: countOf(stats.by_decision, decision) }));
  const sum = counts.reduce((total, entry) => total + entry.count, 0);
  return (
    <Card title="Verdicts" description="All scans by policy decision.">
      {sum === 0 ? (
        <EmptyState compact title="No scans yet." />
      ) : (
        <>
          <div aria-hidden="true" className="flex h-3 w-full gap-[2px] overflow-hidden rounded-sm">
            {counts
              .filter((entry) => entry.count > 0)
              .map((entry) => (
                <span
                  key={entry.decision}
                  className={`h-full ${DECISION_FILL[entry.decision]}`}
                  style={{ flexGrow: entry.count, flexBasis: 0 }}
                />
              ))}
          </div>
          <ul className="mt-3 flex flex-col gap-1.5">
            {counts.map((entry) => (
              <li key={entry.decision} className="flex items-center justify-between gap-3">
                <DecisionBadge value={entry.decision} />
                <span className="tabular-nums text-ink">
                  {formatCount(entry.count)}
                  <span className="ml-2 text-ink-secondary">{formatPercent(entry.count / sum)}</span>
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

function SeverityCard({ stats }: { stats: ScanStats }) {
  const [view, setView] = useState<"chart" | "table">("chart");
  const data = SEVERITIES.map((severity) => ({
    severity,
    label: SEVERITY_LABEL[severity],
    count: countOf(stats.by_severity, severity),
  }));
  const sum = data.reduce((total, entry) => total + entry.count, 0);

  const toggle =
    sum > 0 ? (
      <div role="group" aria-label="Severity view" className="flex rounded-sm border border-line p-0.5">
        {(["chart", "table"] as const).map((option) => (
          <button
            key={option}
            type="button"
            aria-pressed={view === option}
            onClick={() => setView(option)}
            className={`rounded-xs px-2 py-0.5 text-xs ${view === option ? "bg-raised text-ink" : "text-ink-secondary hover:text-ink"}`}
          >
            {option === "chart" ? "Chart" : "Table"}
          </button>
        ))}
      </div>
    ) : undefined;

  return (
    <Card title="Severity" description="All scans by overall severity." actions={toggle}>
      {sum === 0 ? (
        <EmptyState compact title="No scans yet." />
      ) : view === "chart" ? (
        <div className="h-44">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 18, right: 4, bottom: 0, left: 0 }}>
              <CartesianGrid vertical={false} stroke={palette.line} />
              <XAxis
                dataKey="label"
                interval={0}
                tickLine={false}
                axisLine={{ stroke: palette.lineStrong }}
                tick={{ fill: palette.inkSecondary, fontSize: 12 }}
              />
              <YAxis
                allowDecimals={false}
                width={36}
                tickLine={false}
                axisLine={false}
                tick={{ fill: palette.inkMuted, fontSize: 11 }}
              />
              <ChartTooltip
                cursor={{ fill: palette.raised }}
                contentStyle={{
                  background: palette.raised,
                  border: `1px solid ${palette.lineStrong}`,
                  borderRadius: 4,
                }}
                labelStyle={{ color: palette.ink }}
                itemStyle={{ color: palette.ink }}
                formatter={(value) => [formatCount(Number(value)), "Scans"]}
              />
              <Bar dataKey="count" maxBarSize={24} radius={[4, 4, 0, 0]} isAnimationActive={false}>
                {data.map((entry) => (
                  <Cell key={entry.severity} fill={palette.severity[entry.severity]} />
                ))}
                <LabelList dataKey="count" position="top" fill={palette.inkSecondary} fontSize={11} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <table className="w-full text-[0.8125rem]">
          <caption className="sr-only">Scans by severity</caption>
          <thead>
            <tr className="border-b border-line text-left text-xs text-ink-secondary">
              <th scope="col" className="py-1.5 font-medium">
                Severity
              </th>
              <th scope="col" className="py-1.5 text-right font-medium">
                Scans
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((entry) => (
              <tr key={entry.severity} className="border-b border-line/60 last:border-0">
                <td className="py-1.5">
                  <SeverityBadge value={entry.severity} />
                </td>
                <td className="py-1.5 text-right tabular-nums">{formatCount(entry.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function TopCodesCard({ items }: { items: ScanStats["top_signals"] }) {
  const rows = (Array.isArray(items) ? items : []).filter(
    (item) => typeof item.code === "string" && numberOrNull(item.count) !== null,
  );
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <Card title="Most frequent finding codes" description="Across all recorded scans.">
      {rows.length === 0 ? (
        <EmptyState compact title="No findings recorded yet." />
      ) : (
        <ul className="flex flex-col gap-2">
          {rows.map((row) => (
            <li key={row.code} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1">
              <code className="truncate font-mono text-xs text-ink">{row.code}</code>
              <span className="text-right text-xs tabular-nums text-ink-secondary">{formatCount(row.count)}</span>
              <span aria-hidden="true" className="col-span-2 h-1.5 overflow-hidden rounded-full bg-line">
                <span className="block h-full rounded-full bg-accent" style={{ width: `${(row.count / max) * 100}%` }} />
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function Posture({ stats }: { stats: ScanStats }) {
  const total = numberOrNull(stats.total) ?? 0;
  const average = numberOrNull(stats.avg_risk_score);
  const allowed = countOf(stats.by_decision, "allow");
  return (
    <>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Scans recorded" value={total} />
        <StatTile label="Blocked in the last 30 days" value={numberOrNull(stats.blocked_last_30d) ?? 0} />
        <StatTile
          label="Average risk score"
          value={average === null ? "Not recorded" : average.toFixed(1)}
          hint={average === null ? undefined : `${SEVERITY_LABEL[severityForScore(average)]} band, across all scans`}
        />
        <StatTile
          label="Allowed"
          value={allowed}
          hint={total > 0 ? `${formatPercent(allowed / total)} of all scans` : undefined}
        />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <VerdictsCard stats={stats} />
        <SeverityCard stats={stats} />
        <TopCodesCard items={stats.top_signals} />
      </div>
    </>
  );
}

function EventList({ events }: { events: SecurityEvent[] }) {
  if (events.length === 0) return <EmptyState compact title="No security events recorded." />;
  return (
    <Timeline
      label="Latest security events"
      items={events.map((event) => ({
        id: event.id,
        time: event.created_at,
        tone: isSeverity(event.severity) ? event.severity : undefined,
        title: event.title,
        description: (
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <SeverityBadge value={event.severity} />
            <span>{humanize(event.type)}</span>
            {event.package && (
              <code className="break-all font-mono text-xs text-ink">
                {event.package}
                {event.version ? `==${event.version}` : ""}
              </code>
            )}
            {event.scan_id && (
              <Link to={`/scans/${encodeURIComponent(event.scan_id)}`} className="text-xs text-accent hover:underline">
                Open scan
              </Link>
            )}
            {event.acknowledged && <span className="text-xs text-ink-muted">Acknowledged</span>}
          </span>
        ),
      }))}
    />
  );
}

export default function Dashboard() {
  const canScan = usePermission(PERMISSIONS.SCAN_CREATE);
  const stats = useApiQuery("dashboard:stats", (signal) => getScanStats({ signal }));
  const recent = useApiQuery("dashboard:recent-scans", (signal) => listScans({ limit: 8 }, { signal }));
  const events = useApiQuery("dashboard:recent-events", (signal) => listEvents({ limit: 6 }, { signal }));

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Policy verdicts and risk across every package this deployment has analysed."
        actions={
          canScan ? (
            <Link to="/scans/new" className="btn-primary">
              New scan
            </Link>
          ) : undefined
        }
      />
      <div className="flex flex-col gap-4">
        {stats.data ? (
          <Posture stats={stats.data} />
        ) : stats.error ? (
          <ErrorState error={stats.error} onRetry={stats.reload} title="Scan statistics could not be loaded" />
        ) : (
          <LoadingBlock label="Loading scan statistics" rows={4} />
        )}
        <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <Card
            title="Recent scans"
            flush
            actions={
              <Link to="/scans" className="text-xs text-accent hover:underline">
                All scans
              </Link>
            }
          >
            <DataTable
              caption="Recent scans"
              columns={RECENT_SCAN_COLUMNS}
              rows={recent.data?.items}
              rowKey={(scan) => scan.id}
              loading={recent.loading}
              error={recent.error}
              onRetry={recent.reload}
              empty={
                <EmptyState
                  compact
                  title="No scans yet."
                  description={canScan ? "Start one with New scan." : "Scans started by other users appear here."}
                />
              }
            />
          </Card>
          <Card title="Latest security events">
            {events.data ? (
              <EventList events={events.data.items} />
            ) : events.error ? (
              <ErrorState error={events.error} onRetry={events.reload} title="Security events could not be loaded" />
            ) : (
              <LoadingBlock label="Loading security events" />
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
