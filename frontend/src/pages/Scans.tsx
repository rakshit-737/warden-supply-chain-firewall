import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage } from "../api/client";
import type { Decision, Page, ScanSummary } from "../api/types";
import { DecisionBadge, Empty, RiskMeter, SeverityBadge, Spinner } from "../components/ui";

const PAGE = 20;

export default function Scans() {
  const [data, setData] = useState<Page<ScanSummary> | null>(null);
  const [q, setQ] = useState("");
  const [decision, setDecision] = useState<Decision | "">("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params: Record<string, string | number> = { limit: PAGE, offset };
    if (q) params.q = q;
    if (decision) params.decision = decision;
    api
      .get<Page<ScanSummary>>("/scans", { params })
      .then((r) => setData(r.data))
      .catch((e) => setError(apiErrorMessage(e)));
  }, [q, decision, offset]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Scan history</h1>

      <div className="flex flex-wrap gap-3">
        <input
          className="input max-w-xs"
          placeholder="Search package…"
          value={q}
          onChange={(e) => {
            setOffset(0);
            setQ(e.target.value);
          }}
        />
        <select
          className="input max-w-[160px]"
          value={decision}
          onChange={(e) => {
            setOffset(0);
            setDecision(e.target.value as Decision | "");
          }}
        >
          <option value="">All decisions</option>
          <option value="allow">Allow</option>
          <option value="warn">Warn</option>
          <option value="block">Block</option>
        </select>
      </div>

      {error ? (
        <Empty text={error} />
      ) : !data ? (
        <Spinner />
      ) : data.items.length === 0 ? (
        <Empty text="No scans match." />
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-edge text-left text-xs uppercase tracking-wide text-muted">
              <tr>
                <th className="px-4 py-3">Package</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Decision</th>
                <th className="px-4 py-3">When</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((s) => (
                <tr key={s.id} className="border-b border-edge/50 hover:bg-panel2/50">
                  <td className="px-4 py-3">
                    <Link to={`/scans/${s.id}`} className="font-mono text-slate-200 hover:text-accent">
                      {s.package_name}
                      <span className="text-muted">=={s.version}</span>
                    </Link>
                  </td>
                  <td className="px-4 py-3"><RiskMeter score={s.risk_score} /></td>
                  <td className="px-4 py-3"><SeverityBadge value={s.severity} /></td>
                  <td className="px-4 py-3"><DecisionBadge value={s.decision} /></td>
                  <td className="px-4 py-3 text-muted">{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && data.total > PAGE && (
        <div className="flex items-center justify-between text-sm text-muted">
          <span>
            {offset + 1}–{Math.min(offset + PAGE, data.total)} of {data.total}
          </span>
          <div className="flex gap-2">
            <button className="btn-ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              Prev
            </button>
            <button className="btn-ghost" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
