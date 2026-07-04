import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, apiErrorMessage } from "../api/client";
import type { Scan } from "../api/types";
import { DecisionBadge, RiskMeter, SeverityBadge } from "../components/ui";

export default function NewScan() {
  const nav = useNavigate();
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Scan | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const resp = await api.post<Scan>("/scans", {
        ecosystem: "pypi",
        name: name.trim(),
        version: version.trim() || null,
      });
      setResult(resp.data);
    } catch (err) {
      setError(apiErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Analyse a package</h1>
        <p className="text-sm text-muted">Warden fetches the real artifact from PyPI and evaluates it against the active policy.</p>
      </div>

      <form onSubmit={onSubmit} className="card grid gap-4 p-5 sm:grid-cols-[1fr_200px_auto] sm:items-end">
        <div>
          <label className="label">Package name</label>
          <input className="input" placeholder="e.g. requests" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div>
          <label className="label">Version (optional)</label>
          <input className="input" placeholder="latest" value={version} onChange={(e) => setVersion(e.target.value)} />
        </div>
        <button className="btn-primary h-[38px]" disabled={busy || !name.trim()}>
          {busy ? "Scanning…" : "Scan"}
        </button>
      </form>

      {error && <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{error}</div>}

      {result && (
        <div className="card p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="font-mono text-lg">
                {result.package_name}
                <span className="text-muted">=={result.version}</span>
              </div>
              <div className="mt-1 flex items-center gap-2">
                <DecisionBadge value={result.decision} />
                <SeverityBadge value={result.severity} />
                <span className="text-xs text-muted">{result.duration_ms} ms</span>
              </div>
            </div>
            <RiskMeter score={result.risk_score} />
          </div>

          <div className="mt-4 grid grid-cols-3 gap-3 text-sm">
            <div className="rounded-lg bg-panel2 p-3">
              <div className="text-xs text-muted">Rule score</div>
              <div className="text-lg">{result.rule_score}</div>
            </div>
            <div className="rounded-lg bg-panel2 p-3">
              <div className="text-xs text-muted">ML score</div>
              <div className="text-lg">{result.ml_score}</div>
            </div>
            <div className="rounded-lg bg-panel2 p-3">
              <div className="text-xs text-muted">Fused risk</div>
              <div className="text-lg">{result.risk_score}</div>
            </div>
          </div>

          {result.matched_policy_rules.length > 0 && (
            <div className="mt-4">
              <div className="label">Matched policy rules</div>
              <div className="flex flex-wrap gap-2">
                {result.matched_policy_rules.map((r) => (
                  <span key={r} className="rounded-md bg-panel2 px-2 py-1 font-mono text-xs text-slate-300">{r}</span>
                ))}
              </div>
            </div>
          )}

          <button className="btn-ghost mt-5" onClick={() => nav(`/scans/${result.id}`)}>
            View full signal breakdown →
          </button>
        </div>
      )}
    </div>
  );
}
