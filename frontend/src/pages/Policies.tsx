import { useEffect, useState } from "react";
import { api, apiErrorMessage } from "../api/client";
import type { Policy } from "../api/types";
import { Empty, Spinner } from "../components/ui";
import { useAuth } from "../auth/AuthContext";

export default function Policies() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [policies, setPolicies] = useState<Policy[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [draft, setDraft] = useState<Partial<Policy> | null>(null);

  async function load() {
    try {
      const r = await api.get<Policy[]>("/policies");
      setPolicies(r.data);
      const active = r.data.find((p) => p.is_active) || r.data[0];
      if (active) setDraft({ ...active });
    } catch (e) {
      setError(apiErrorMessage(e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function save() {
    if (!draft?.id) return;
    setNote(null);
    try {
      await api.put(`/policies/${draft.id}`, {
        name: draft.name,
        warn_threshold: draft.warn_threshold,
        block_threshold: draft.block_threshold,
        min_package_age_days: draft.min_package_age_days,
        blocked_capabilities: draft.blocked_capabilities ?? [],
        allowlist: draft.allowlist ?? [],
        denylist: draft.denylist ?? [],
      });
      setNote("Policy saved.");
      await load();
    } catch (e) {
      setError(apiErrorMessage(e));
    }
  }

  async function activate(id: string) {
    try {
      await api.post(`/policies/${id}/activate`);
      await load();
    } catch (e) {
      setError(apiErrorMessage(e));
    }
  }

  if (error) return <Empty text={error} />;
  if (!policies || !draft) return <Spinner />;

  const list = (arr?: string[]) => (arr ?? []).join(", ");
  const parse = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Enforcement policy</h1>
        <p className="text-sm text-muted">
          Controls how verdicts map to allow / warn / block.{" "}
          {!isAdmin && <span className="text-amber-300">Read-only — admin role required to edit.</span>}
        </p>
      </div>

      <div className="card space-y-4 p-5">
        <div className="grid gap-4 sm:grid-cols-3">
          <div>
            <label className="label">Warn threshold ({draft.warn_threshold})</label>
            <input type="range" min={0} max={100} value={draft.warn_threshold ?? 40} disabled={!isAdmin}
              onChange={(e) => setDraft({ ...draft, warn_threshold: Number(e.target.value) })} className="w-full" />
          </div>
          <div>
            <label className="label">Block threshold ({draft.block_threshold})</label>
            <input type="range" min={0} max={100} value={draft.block_threshold ?? 70} disabled={!isAdmin}
              onChange={(e) => setDraft({ ...draft, block_threshold: Number(e.target.value) })} className="w-full" />
          </div>
          <div>
            <label className="label">Min package age (days)</label>
            <input type="number" min={0} className="input" value={draft.min_package_age_days ?? 0} disabled={!isAdmin}
              onChange={(e) => setDraft({ ...draft, min_package_age_days: Number(e.target.value) })} />
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <div>
            <label className="label">Blocked capabilities (comma-sep)</label>
            <input className="input" disabled={!isAdmin} value={list(draft.blocked_capabilities)}
              onChange={(e) => setDraft({ ...draft, blocked_capabilities: parse(e.target.value) })} />
          </div>
          <div>
            <label className="label">Allowlist</label>
            <input className="input" disabled={!isAdmin} value={list(draft.allowlist)}
              onChange={(e) => setDraft({ ...draft, allowlist: parse(e.target.value) })} />
          </div>
          <div>
            <label className="label">Denylist</label>
            <input className="input" disabled={!isAdmin} value={list(draft.denylist)}
              onChange={(e) => setDraft({ ...draft, denylist: parse(e.target.value) })} />
          </div>
        </div>

        {isAdmin && (
          <div className="flex items-center gap-3">
            <button className="btn-primary" onClick={save}>Save changes</button>
            {note && <span className="text-sm text-emerald-300">{note}</span>}
          </div>
        )}
      </div>

      <div className="card p-5">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">All policies</h2>
        <ul className="space-y-2">
          {policies.map((p) => (
            <li key={p.id} className="flex items-center justify-between rounded-lg bg-panel2/50 px-3 py-2 text-sm">
              <span>
                {p.name}{" "}
                {p.is_active && <span className="ml-2 rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">active</span>}
              </span>
              {isAdmin && !p.is_active && (
                <button className="btn-ghost" onClick={() => activate(p.id)}>Activate</button>
              )}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
