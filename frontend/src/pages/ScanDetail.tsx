import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, apiErrorMessage } from "../api/client";
import type { Scan } from "../api/types";
import { DecisionBadge, Empty, RiskMeter, SeverityBadge, Spinner } from "../components/ui";

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Scan>(`/scans/${id}`)
      .then((r) => setScan(r.data))
      .catch((e) => setError(apiErrorMessage(e)));
  }, [id]);

  if (error) return <Empty text={error} />;
  if (!scan) return <Spinner />;

  const features = Object.entries(scan.feature_vector)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-6">
      <Link to="/scans" className="text-sm text-muted hover:text-accent">← Back to history</Link>

      <div className="card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-mono text-xl">
              {scan.package_name}
              <span className="text-muted">=={scan.version}</span>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <DecisionBadge value={scan.decision} />
              <SeverityBadge value={scan.severity} />
              <span className="text-xs text-muted">analyzer v{scan.analyzer_version} · {scan.duration_ms} ms</span>
            </div>
          </div>
          <RiskMeter score={scan.risk_score} />
        </div>
        <div className="mt-4 grid grid-cols-3 gap-3 text-sm">
          <div className="rounded-lg bg-panel2 p-3"><div className="text-xs text-muted">Rule</div><div className="text-lg">{scan.rule_score}</div></div>
          <div className="rounded-lg bg-panel2 p-3"><div className="text-xs text-muted">ML</div><div className="text-lg">{scan.ml_score}</div></div>
          <div className="rounded-lg bg-panel2 p-3"><div className="text-xs text-muted">Fused</div><div className="text-lg">{scan.risk_score}</div></div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <div className="card p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Signals ({scan.signals.length})</h2>
          {scan.signals.length === 0 ? (
            <Empty text="No risk signals — package looks clean." />
          ) : (
            <ul className="space-y-3">
              {[...scan.signals]
                .sort((a, b) => b.weight - a.weight)
                .map((s, i) => (
                  <li key={i} className="rounded-lg border border-edge bg-panel2/50 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-slate-200">{s.code}</span>
                      <div className="flex items-center gap-2">
                        <SeverityBadge value={s.severity} />
                        <span className="text-xs text-muted">w={s.weight}</span>
                      </div>
                    </div>
                    <p className="mt-1 text-sm text-slate-300">{s.message}</p>
                    {Object.keys(s.evidence || {}).length > 0 && (
                      <pre className="mt-2 overflow-x-auto rounded bg-base/60 p-2 text-[11px] text-muted">
                        {JSON.stringify(s.evidence, null, 2)}
                      </pre>
                    )}
                  </li>
                ))}
            </ul>
          )}
        </div>

        <div className="card p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">ML feature contributions</h2>
          {features.length === 0 ? (
            <Empty text="No active features." />
          ) : (
            <ul className="space-y-2">
              {features.map(([name, value]) => (
                <li key={name} className="flex items-center gap-3">
                  <span className="w-40 truncate font-mono text-xs text-slate-300">{name}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-panel2">
                    <div className="h-full bg-accent" style={{ width: `${Math.min(100, value * 100)}%` }} />
                  </div>
                  <span className="w-10 text-right text-xs tabular-nums text-muted">{value.toFixed(2)}</span>
                </li>
              ))}
            </ul>
          )}
          {scan.matched_policy_rules.length > 0 && (
            <div className="mt-5">
              <div className="label">Matched policy rules</div>
              <div className="flex flex-wrap gap-2">
                {scan.matched_policy_rules.map((r) => (
                  <span key={r} className="rounded-md bg-panel2 px-2 py-1 font-mono text-xs text-slate-300">{r}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
