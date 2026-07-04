import { useEffect, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { api, apiErrorMessage } from "../api/client";
import type { ScanStats } from "../api/types";
import { Empty, Spinner, StatCard } from "../components/ui";

const DECISION_COLORS: Record<string, string> = {
  allow: "#34d399",
  warn: "#fbbf24",
  block: "#fb7185",
};

export default function Dashboard() {
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<ScanStats>("/scans/stats/overview")
      .then((r) => setStats(r.data))
      .catch((e) => setError(apiErrorMessage(e)));
  }, []);

  if (error) return <Empty text={error} />;
  if (!stats) return <Spinner />;

  const pie = Object.entries(stats.by_decision).map(([name, value]) => ({ name, value }));
  const hasData = stats.total > 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Risk Posture</h1>
        <p className="text-sm text-muted">Organisation-wide view of analysed dependencies.</p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total scans" value={stats.total} />
        <StatCard label="Blocked (30d)" value={stats.blocked_last_30d} sub="policy-enforced" />
        <StatCard label="Avg risk score" value={stats.avg_risk_score} sub="0–100" />
        <StatCard label="Allowed" value={stats.by_decision.allow ?? 0} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Verdict distribution</h2>
          {hasData ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pie} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
                  {pie.map((entry) => (
                    <Cell key={entry.name} fill={DECISION_COLORS[entry.name] || "#64748b"} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#131a2a", border: "1px solid #28324a", borderRadius: 8 }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <Empty text="No scans yet — run one from New Scan." />
          )}
          <div className="mt-2 flex justify-center gap-4 text-xs text-muted">
            {pie.map((p) => (
              <span key={p.name} className="flex items-center gap-1">
                <span className="h-2 w-2 rounded-full" style={{ background: DECISION_COLORS[p.name] }} />
                {p.name} ({p.value})
              </span>
            ))}
          </div>
        </div>

        <div className="card p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Most frequent signals</h2>
          {stats.top_signals.length ? (
            <ul className="space-y-2">
              {stats.top_signals.map((s) => {
                const max = stats.top_signals[0].count || 1;
                return (
                  <li key={s.code} className="flex items-center gap-3">
                    <span className="w-40 truncate font-mono text-xs text-slate-300">{s.code}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-panel2">
                      <div className="h-full bg-accent" style={{ width: `${(s.count / max) * 100}%` }} />
                    </div>
                    <span className="w-8 text-right text-xs tabular-nums text-muted">{s.count}</span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <Empty text="No signals recorded yet." />
          )}
        </div>
      </div>
    </div>
  );
}
