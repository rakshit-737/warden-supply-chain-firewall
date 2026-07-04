import { ReactNode } from "react";
import type { Decision, Severity } from "../api/types";

const decisionStyles: Record<Decision, string> = {
  allow: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  warn: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  block: "bg-rose-500/15 text-rose-300 border-rose-500/30",
};

const severityStyles: Record<Severity, string> = {
  info: "bg-slate-500/15 text-slate-300 border-slate-500/30",
  low: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  critical: "bg-rose-500/15 text-rose-300 border-rose-500/30",
};

export function DecisionBadge({ value }: { value: Decision }) {
  return (
    <span className={`inline-block rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${decisionStyles[value]}`}>
      {value}
    </span>
  );
}

export function SeverityBadge({ value }: { value: Severity }) {
  return (
    <span className={`inline-block rounded-md border px-2 py-0.5 text-xs font-medium capitalize ${severityStyles[value]}`}>
      {value}
    </span>
  );
}

export function RiskMeter({ score }: { score: number }) {
  const color =
    score >= 80 ? "bg-rose-500" : score >= 60 ? "bg-orange-500" : score >= 35 ? "bg-amber-500" : score >= 15 ? "bg-sky-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-28 overflow-hidden rounded-full bg-panel2">
        <div className={`h-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="w-8 text-right text-sm tabular-nums text-slate-300">{score}</span>
    </div>
  );
}

export function StatCard({ label, value, sub }: { label: string; value: ReactNode; sub?: string }) {
  return (
    <div className="card p-4">
      <div className="text-xs uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-100">{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </div>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-10 text-muted">
      <div className="h-5 w-5 animate-spin rounded-full border-2 border-edge border-t-accent" />
    </div>
  );
}

export function Empty({ text }: { text: string }) {
  return <div className="py-10 text-center text-sm text-muted">{text}</div>;
}
