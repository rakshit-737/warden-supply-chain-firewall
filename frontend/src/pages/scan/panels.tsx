import { useState, type ReactNode } from "react";
import { toApiError } from "../../api/client";
import { getScanReport } from "../../api/scans";
import {
  REPORT_FORMATS,
  SEVERITIES,
  type AnalyzerRun,
  type AttackChain,
  type Finding,
  type IntelStatus,
  type PolicyDecisionReason,
  type ProvenanceSummary,
  type ReportFormat,
  type RiskFloor,
  type Scan,
  type Severity,
  type Vulnerability,
} from "../../api/types";
import { AttackChainView, type LinkedFinding } from "../../components/AttackChainView";
import { Card } from "../../components/Card";
import { CodeBlock } from "../../components/CodeBlock";
import { ConfidencePill } from "../../components/ConfidencePill";
import { DataTable, type Column } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { ExternalLink } from "../../components/ExternalLink";
import { FindingCard } from "../../components/FindingCard";
import { KeyValueList } from "../../components/KeyValueList";
import { RiskBreakdownBars } from "../../components/RiskBreakdownBars";
import { RiskGauge } from "../../components/RiskGauge";
import { SelectField } from "../../components/SelectField";
import { SeverityBadge } from "../../components/SeverityBadge";
import { downloadText, safeFileName } from "../../lib/download";
import { findingAnchorId } from "../../lib/findings";
import { formatDateTime, formatDuration, humanize } from "../../lib/format";
import { severityRank } from "../../lib/risk";
import { mlModelUsed } from "../../lib/scan";
import { safeHttpUrl } from "../../lib/url";
import {
  booleanOrNull,
  isRecord,
  numberOrNull,
  pickOption,
  recordArray,
  stringArray,
  textOrNull,
} from "../../lib/values";

// ---------------------------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------------------------

export function ScanMeta({ scan }: { scan: Scan }) {
  const environment = textOrNull(scan.environment);
  const items: [string, ReactNode][] = [
    ["Ecosystem", textOrNull(scan.ecosystem) ?? "Not recorded"],
    ["Environment", environment ? humanize(environment) : "Not recorded"],
    ["Scanned", <time dateTime={scan.created_at}>{formatDateTime(scan.created_at)}</time>],
    ["Analyzer", textOrNull(scan.analyzer_version) ?? "Not recorded"],
    ["Model", textOrNull(scan.model_version) ?? "Not recorded"],
    ["Duration", formatDuration(scan.duration_ms)],
  ];
  return (
    <dl className="flex flex-wrap gap-x-5 gap-y-1 text-xs">
      {items.map(([term, value]) => (
        <div key={term} className="flex gap-1.5">
          <dt className="text-ink-muted">{term}</dt>
          <dd className="break-all text-ink-secondary">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

const REPORT_LABEL: Record<ReportFormat, string> = { json: "JSON", markdown: "Markdown", html: "HTML", sarif: "SARIF" };
const REPORT_FILE: Record<ReportFormat, { suffix: string; extension: string }> = {
  json: { suffix: "", extension: "json" },
  markdown: { suffix: "", extension: "md" },
  html: { suffix: "", extension: "html" },
  sarif: { suffix: ".sarif", extension: "json" },
};

/** Report download. Reports are saved as files and never rendered inside the console. */
export function ReportExport({ scan }: { scan: Scan }) {
  const [format, setFormat] = useState<ReportFormat>("json");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setError(null);
    try {
      const text = await getScanReport(scan.id, format);
      const file = REPORT_FILE[format];
      downloadText(safeFileName(`warden-${scan.package_name}-${scan.version}-report${file.suffix}`, file.extension), text);
    } catch (err) {
      const apiError = toApiError(err);
      setError(apiError.status === 404 ? "This server does not provide report exports." : apiError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col items-start gap-1 sm:items-end">
      <div className="flex items-end gap-2">
        <SelectField
          id="report-format"
          label="Report format"
          className="w-32"
          value={format}
          options={REPORT_FORMATS.map((f) => ({ value: f, label: REPORT_LABEL[f] }))}
          onChange={(value) => setFormat(pickOption(REPORT_FORMATS, value) ?? "json")}
        />
        <button type="button" className="btn-secondary" disabled={busy} onClick={() => void download()}>
          {busy ? "Preparing" : "Download report"}
        </button>
      </div>
      {error && (
        <p role="alert" className="max-w-xs text-xs text-ink-secondary">
          {error}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------------------------

function FindingLink({
  findingId,
  findings,
  onFindingClick,
}: {
  findingId: string;
  findings: ReadonlyMap<string, LinkedFinding>;
  onFindingClick: (findingId: string) => void;
}) {
  return (
    <a
      href={`#${findingAnchorId(findingId)}`}
      onClick={(event) => {
        event.preventDefault();
        onFindingClick(findingId);
      }}
      className="inline-flex rounded border border-line px-1.5 py-0.5 font-mono text-2xs text-ink-secondary hover:border-accent hover:text-ink"
    >
      {findings.get(findingId)?.code ?? findingId}
    </a>
  );
}

export function PolicyOutcome({
  scan,
  findings,
  onFindingClick,
}: {
  scan: Scan;
  findings: ReadonlyMap<string, LinkedFinding>;
  onFindingClick: (findingId: string) => void;
}) {
  const reasons = (recordArray<PolicyDecisionReason>(scan.policy_reasons) ?? []).filter(
    (reason) => textOrNull(reason.rule) !== null,
  );
  const rules = stringArray(scan.matched_policy_rules);
  const environment = textOrNull(scan.environment);
  return (
    <div className="border-t border-line pt-3">
      <h3 className="text-xs font-semibold text-ink">Policy</h3>
      <p className="mt-0.5 text-xs text-ink-secondary">
        {environment
          ? `Evaluated for the ${humanize(environment).toLowerCase()} environment.`
          : "Evaluated against the policy that was active when the scan ran."}
      </p>
      {reasons.length > 0 ? (
        <ul className="mt-1 divide-y divide-line">
          {reasons.map((reason, index) => {
            const ids = stringArray(reason.finding_ids);
            return (
              <li key={`${reason.rule}-${index}`} className="py-2">
                <code className="break-all font-mono text-xs text-ink">{reason.rule}</code>
                {textOrNull(reason.detail) && <p className="break-words text-ink-secondary">{reason.detail}</p>}
                {ids.length > 0 && (
                  <ul aria-label="Findings behind this rule" className="mt-1 flex flex-wrap gap-1.5">
                    {ids.map((id) => (
                      <li key={id}>
                        <FindingLink findingId={id} findings={findings} onFindingClick={onFindingClick} />
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
        </ul>
      ) : rules.length > 0 ? (
        <ul aria-label="Matched policy rules" className="mt-2 flex flex-wrap gap-1.5">
          {rules.map((rule) => (
            <li key={rule}>
              <code className="break-all rounded bg-raised px-1.5 py-0.5 font-mono text-2xs text-ink">{rule}</code>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-ink-muted">No policy rules matched.</p>
      )}
    </div>
  );
}

export function ScoresList({ scan }: { scan: Scan }) {
  const risk = isRecord(scan.risk) ? scan.risk : null;
  const malicious = numberOrNull(scan.malicious_risk) ?? numberOrNull(risk?.malicious_risk);
  const vulnerabilityRecorded = scan.vulnerability_risk !== undefined || (risk !== null && "vulnerability_risk" in risk);
  const vulnerability = numberOrNull(scan.vulnerability_risk) ?? numberOrNull(risk?.vulnerability_risk);
  const modelUsed = mlModelUsed(scan);
  // `missing` replaces the gauge. The server records ml_score 0 when no model ran, which as a gauge
  // would read as "the model judged this package low risk".
  const rows: { label: string; hint: string; score: number | null; missing: string | null }[] = [
    {
      label: "Rule engine",
      hint: "Weighted findings from deterministic rules.",
      score: numberOrNull(scan.rule_score),
      missing: null,
    },
    {
      label: "ML model",
      hint:
        modelUsed === false
          ? "No machine-learning model ran for this scan."
          : "Estimate from the machine-learning model.",
      score: numberOrNull(scan.ml_score),
      missing: modelUsed === false ? "Model not available" : null,
    },
    {
      label: "Malicious risk",
      hint: "Rule and model scores combined.",
      score: malicious,
      missing: malicious !== null ? null : "Not recorded",
    },
    {
      label: "Vulnerability risk",
      hint: "From the worst known vulnerability. Unknown when intelligence was unavailable.",
      score: vulnerability,
      missing: vulnerabilityRecorded ? null : "Not recorded",
    },
  ];
  return (
    <div className="flex flex-col">
      <ul className="divide-y divide-line">
        {rows.map((row) => (
          <li key={row.label} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 py-2 first:pt-0">
            <div className="min-w-0">
              <div className="text-ink">{row.label}</div>
              <div className="text-xs text-ink-muted">{row.hint}</div>
            </div>
            {row.missing === null ? (
              <RiskGauge score={row.score} size="sm" label={row.label} />
            ) : (
              <span className="text-xs text-ink-muted">{row.missing}</span>
            )}
          </li>
        ))}
      </ul>
      {risk && (
        <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line pt-3 text-xs text-ink-secondary">
          <span className="inline-flex items-center gap-1.5">
            Overall <ConfidencePill value={numberOrNull(risk.confidence)} />
          </span>
          {textOrNull(risk.method) && (
            <span>
              Method <code className="font-mono text-ink">{risk.method}</code>
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------------------------

export function FindingsPanel({
  findings,
  severity,
  onSeverityChange,
}: {
  findings: readonly Finding[];
  severity: Severity | "all";
  onSeverityChange: (severity: Severity | "all") => void;
}) {
  if (findings.length === 0) return <EmptyState compact title="No findings were recorded for this scan." />;
  const counts = [...SEVERITIES]
    .reverse()
    .map((level) => ({ level, count: findings.filter((finding) => finding.severity === level).length }))
    .filter((entry) => entry.count > 0);
  const shown = severity === "all" ? findings : findings.filter((finding) => finding.severity === severity);
  const chip = (pressed: boolean) =>
    `inline-flex items-center gap-2 rounded border px-2 py-1 text-xs ${
      pressed ? "border-accent bg-raised text-ink" : "border-line text-ink-secondary hover:border-line-strong hover:text-ink"
    }`;
  return (
    <div className="flex flex-col gap-3">
      <div role="group" aria-label="Filter findings by severity" className="flex flex-wrap gap-1.5">
        <button type="button" aria-pressed={severity === "all"} className={chip(severity === "all")} onClick={() => onSeverityChange("all")}>
          All <span className="tabular-nums">{findings.length}</span>
        </button>
        {counts.map(({ level, count }) => (
          <button
            key={level}
            type="button"
            aria-pressed={severity === level}
            className={chip(severity === level)}
            onClick={() => onSeverityChange(level)}
          >
            <SeverityBadge value={level} /> <span className="tabular-nums">{count}</span>
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <EmptyState compact title="No findings at this severity." />
      ) : (
        shown.map((finding, index) => (
          <FindingCard key={`${finding.finding_id ?? finding.code}-${index}`} finding={finding} />
        ))
      )}
    </div>
  );
}

function formatFeature(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

export function RiskPanel({ scan }: { scan: Scan }) {
  const risk = isRecord(scan.risk) ? scan.risk : null;
  const floors = recordArray<RiskFloor>(risk?.floors_applied) ?? [];
  const features = Object.entries(isRecord(scan.feature_vector) ? scan.feature_vector : {})
    .map(([name, value]) => ({ name, value: numberOrNull(value) }))
    .filter((entry): entry is { name: string; value: number } => entry.value !== null && entry.value > 0)
    .sort((a, b) => b.value - a.value);
  const largest = features.reduce((max, entry) => Math.max(max, entry.value), 0);

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <Card title="Risk dimensions" description="Each dimension scores 0 to 100. Unknown means it could not be assessed.">
        {risk ? (
          <>
            <RiskBreakdownBars dimensions={risk.dimensions} />
            {floors.length > 0 && (
              <div className="mt-3 border-t border-line pt-3">
                <h3 className="text-xs font-semibold text-ink">Score floors applied</h3>
                <ul className="mt-1 flex flex-col gap-1 text-xs text-ink-secondary">
                  {floors.map((floor, index) => {
                    const minimum = numberOrNull(floor.minimum);
                    const codes = stringArray(floor.codes);
                    return (
                      <li key={`${textOrNull(floor.rule) ?? "floor"}-${index}`} className="break-words">
                        <code className="font-mono text-ink">{textOrNull(floor.rule) ?? "Unnamed floor"}</code>
                        {minimum !== null && ` sets a minimum final score of ${minimum}`}
                        {codes.length > 0 && ` (${codes.join(", ")})`}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </>
        ) : (
          <EmptyState
            compact
            title="Risk dimensions were not recorded for this scan."
            description="Only the rule, model and final scores are available."
          />
        )}
      </Card>
      <Card
        title="Model input features"
        description="Non-zero values the ML model received. Bars are relative to the largest value."
      >
        {features.length === 0 ? (
          <EmptyState compact title="No non-zero features were recorded." />
        ) : (
          <ul className="flex flex-col gap-1.5">
            {features.map((entry) => (
              <li key={entry.name} className="grid grid-cols-[minmax(0,11rem)_minmax(0,1fr)_3.5rem] items-center gap-3">
                <code className="truncate font-mono text-xs text-ink-secondary">{entry.name}</code>
                <span aria-hidden="true" className="h-1.5 overflow-hidden rounded-full bg-line">
                  <span
                    className="block h-full rounded-full bg-accent"
                    style={{ width: `${largest > 0 ? (entry.value / largest) * 100 : 0}%` }}
                  />
                </span>
                <span className="text-right text-xs tabular-nums text-ink">{formatFeature(entry.value)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

export function AttackChainsPanel({
  chains,
  findings,
  onFindingClick,
}: {
  chains: AttackChain[] | null;
  findings: ReadonlyMap<string, LinkedFinding>;
  onFindingClick: (findingId: string) => void;
}) {
  if (chains === null) return <EmptyState compact title="Attack-chain correlation was not recorded for this scan." />;
  if (chains.length === 0) {
    return <EmptyState compact title="No attack chains were correlated from this scan's findings." />;
  }
  return <AttackChainView chains={chains} findings={findings} onFindingClick={onFindingClick} />;
}

function referenceLabel(value: string): string {
  const url = safeHttpUrl(value);
  if (url === null) return value;
  try {
    return new URL(url).hostname;
  } catch {
    return value;
  }
}

function formatProbability(value: number): string {
  const percent = Math.min(1, Math.max(0, value)) * 100;
  return `${percent.toFixed(percent < 10 ? 2 : 1)}%`;
}

const VULNERABILITY_COLUMNS: Column<Vulnerability>[] = [
  {
    id: "id",
    header: "Advisory",
    sortValue: (vuln) => vuln.id,
    cell: (vuln) => {
      const aliases = stringArray(vuln.aliases).slice(0, 3);
      return (
        <div className="min-w-0 max-w-md">
          <code className="break-all font-mono text-xs text-ink">{vuln.id}</code>
          {aliases.length > 0 && <div className="break-all text-2xs text-ink-muted">{aliases.join(", ")}</div>}
          {textOrNull(vuln.summary) && <div className="mt-0.5 break-words text-xs text-ink-secondary">{vuln.summary}</div>}
        </div>
      );
    },
  },
  {
    id: "severity",
    header: "Severity",
    sortValue: (vuln) => severityRank(vuln.severity),
    cell: (vuln) => <SeverityBadge value={vuln.severity} />,
  },
  {
    id: "cvss",
    header: "CVSS",
    align: "right",
    sortValue: (vuln) => numberOrNull(vuln.cvss_score),
    cell: (vuln) => {
      const score = numberOrNull(vuln.cvss_score);
      if (score === null) return <span className="text-xs text-ink-muted">Not scored</span>;
      return (
        <span>
          {score.toFixed(1)}
          {textOrNull(vuln.cvss_version) && <span className="ml-1 text-2xs text-ink-muted">v{vuln.cvss_version}</span>}
        </span>
      );
    },
  },
  {
    id: "kev",
    header: "Known exploited",
    sortValue: (vuln) => vuln.kev === true,
    cell: (vuln) =>
      vuln.kev === true ? (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-semibold text-ink">
          <span aria-hidden="true" className="h-2 w-2 rounded-sm bg-sev-critical" />
          In CISA KEV
        </span>
      ) : (
        <span className="text-xs text-ink-muted">No</span>
      ),
  },
  {
    id: "epss",
    header: "EPSS",
    align: "right",
    sortValue: (vuln) => numberOrNull(vuln.epss_score),
    cell: (vuln) => {
      const epss = numberOrNull(vuln.epss_score);
      return epss === null ? <span className="text-xs text-ink-muted">Not recorded</span> : formatProbability(epss);
    },
  },
  {
    id: "fixed",
    header: "Fixed in",
    cell: (vuln) => {
      const fixed = stringArray(vuln.fixed_versions);
      return fixed.length > 0 ? (
        <span className="break-all font-mono text-xs">{fixed.join(", ")}</span>
      ) : (
        <span className="text-xs text-ink-muted">No fix listed</span>
      );
    },
  },
  {
    id: "references",
    header: "References",
    cell: (vuln) => {
      const references = stringArray(vuln.references).slice(0, 3);
      return references.length > 0 ? (
        <ul className="flex flex-col gap-0.5 text-xs">
          {references.map((reference) => (
            <li key={reference}>
              <ExternalLink href={reference}>{referenceLabel(reference)}</ExternalLink>
            </li>
          ))}
        </ul>
      ) : (
        <span className="text-xs text-ink-muted">None</span>
      );
    },
  },
];

function IntelStatusDetails({ intel }: { intel: IntelStatus }) {
  const sources = isRecord(intel.sources)
    ? Object.entries(intel.sources).filter((entry): entry is [string, string] => typeof entry[1] === "string")
    : [];
  const status = textOrNull(intel.status);
  const fetchedAt = textOrNull(intel.fetched_at);
  return (
    <KeyValueList
      items={[
        { term: "Status", value: status ? humanize(status) : null },
        {
          term: "Sources",
          value:
            sources.length > 0 ? (
              <ul className="flex flex-col gap-0.5">
                {sources.map(([source, state]) => (
                  <li key={source}>
                    <code className="font-mono text-xs text-ink">{source}</code>{" "}
                    <span className="text-ink-secondary">{humanize(state).toLowerCase()}</span>
                  </li>
                ))}
              </ul>
            ) : null,
        },
        { term: "Fetched", value: fetchedAt ? formatDateTime(fetchedAt) : null },
        { term: "Reason", value: textOrNull(intel.reason) },
      ]}
    />
  );
}

export function VulnerabilitiesPanel({
  vulnerabilities,
  intel,
}: {
  vulnerabilities: Vulnerability[] | null;
  intel: IntelStatus | null;
}) {
  const status = intel ? textOrNull(intel.status) : null;
  return (
    <div className="flex flex-col gap-4">
      {intel && (
        <Card title="Intelligence sources">
          <IntelStatusDetails intel={intel} />
        </Card>
      )}
      {vulnerabilities === null ? (
        <EmptyState compact title="Vulnerability intelligence was not recorded for this scan." />
      ) : (
        <Card title="Known vulnerabilities" flush>
          <DataTable
            caption="Known vulnerabilities"
            columns={VULNERABILITY_COLUMNS}
            rows={vulnerabilities}
            rowKey={(vuln) => vuln.id}
            defaultSort={{ columnId: "severity", direction: "desc" }}
            empty={
              status === "ok" ? (
                <EmptyState
                  compact
                  title="No known vulnerabilities affect this version."
                  description="According to the intelligence sources listed above."
                />
              ) : (
                <EmptyState
                  compact
                  title="No vulnerabilities were returned."
                  description={
                    status
                      ? `Intelligence status was "${humanize(status).toLowerCase()}", so this is not a clean result.`
                      : "The intelligence status was not recorded, so this is not a clean result."
                  }
                />
              )
            }
          />
        </Card>
      )}
    </div>
  );
}

const KNOWN_PROVENANCE_KEYS = new Set(["status", "attested", "publisher", "source_repository", "hash_verified", "detail"]);

function displayValue(value: unknown): ReactNode {
  if (value === null || value === undefined) return null;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  return <CodeBlock value={value} />;
}

export function ProvenancePanel({ provenance }: { provenance: ProvenanceSummary | null }) {
  if (!provenance) return <EmptyState compact title="Provenance was not recorded for this scan." />;
  const publisher = isRecord(provenance.publisher) ? provenance.publisher : null;
  const repository = textOrNull(provenance.source_repository);
  const publisherRepository = textOrNull(publisher?.repository);
  const status = textOrNull(provenance.status);
  const extras = Object.entries(provenance).filter(([key]) => !KNOWN_PROVENANCE_KEYS.has(key));
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Summary">
        <KeyValueList
          items={[
            { term: "Status", value: status ? humanize(status) : null },
            { term: "Attestation present", value: booleanOrNull(provenance.attested) },
            { term: "Hashes verified", value: booleanOrNull(provenance.hash_verified) },
            { term: "Source repository", value: repository ? <ExternalLink href={repository} /> : null },
            { term: "Publisher", value: textOrNull(publisher?.kind) },
            {
              term: "Publisher repository",
              value: publisherRepository ? <ExternalLink href={publisherRepository} /> : null,
            },
            { term: "Workflow", value: textOrNull(publisher?.workflow), mono: true },
            { term: "Publishing environment", value: textOrNull(publisher?.environment) },
            { term: "Detail", value: textOrNull(provenance.detail) },
          ]}
        />
      </Card>
      {extras.length > 0 && (
        <Card title="Other recorded fields">
          <KeyValueList items={extras.map(([key, value]) => ({ key, term: humanize(key), value: displayValue(value) }))} />
        </Card>
      )}
    </div>
  );
}

interface RunRow {
  key: string;
  run: AnalyzerRun;
}

const RUN_STATUS: Partial<Record<string, { label: string; dot: string }>> = {
  ok: { label: "Completed", dot: "bg-verdict-allow" },
  error: { label: "Error", dot: "bg-sev-critical" },
  timeout: { label: "Timed out", dot: "bg-sev-high" },
  skipped: { label: "Skipped", dot: "bg-ink-muted" },
  unavailable: { label: "Tool unavailable", dot: "bg-sev-medium" },
};

const RUN_COLUMNS: Column<RunRow>[] = [
  {
    id: "name",
    header: "Analyzer",
    sortValue: (row) => textOrNull(row.run.name),
    cell: (row) => <code className="break-all font-mono text-xs text-ink">{textOrNull(row.run.name) ?? "Unnamed"}</code>,
  },
  {
    id: "version",
    header: "Version",
    cell: (row) => textOrNull(row.run.version) ?? <span className="text-xs text-ink-muted">Not recorded</span>,
  },
  {
    id: "status",
    header: "Status",
    sortValue: (row) => textOrNull(row.run.status),
    cell: (row) => {
      const status = textOrNull(row.run.status);
      const meta = status ? RUN_STATUS[status] : undefined;
      return (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span aria-hidden="true" className={`h-2 w-2 rounded-full ${meta?.dot ?? "bg-ink-muted"}`} />
          {meta?.label ?? (status ? humanize(status) : "Not recorded")}
        </span>
      );
    },
  },
  {
    id: "duration",
    header: "Duration",
    align: "right",
    sortValue: (row) => numberOrNull(row.run.duration_ms),
    cell: (row) => formatDuration(numberOrNull(row.run.duration_ms)),
  },
  {
    id: "findings",
    header: "Findings",
    align: "right",
    sortValue: (row) => numberOrNull(row.run.finding_count),
    cell: (row) => numberOrNull(row.run.finding_count) ?? "Not recorded",
  },
  {
    id: "detail",
    header: "Detail",
    cell: (row) =>
      textOrNull(row.run.detail) ? (
        <span className="break-words text-xs text-ink-secondary">{row.run.detail}</span>
      ) : (
        <span className="text-xs text-ink-muted">None</span>
      ),
  },
];

export function AnalyzerRunsPanel({ runs }: { runs: AnalyzerRun[] | null }) {
  if (runs === null) return <EmptyState compact title="Analyzer run details were not recorded for this scan." />;
  const rows = runs.map((run, index) => ({ key: `${textOrNull(run.name) ?? "run"}-${index}`, run }));
  return (
    <Card title="Analyzer runs" description="Outcome of each analyzer. Tools that were not available are listed with that status." flush>
      <DataTable
        caption="Analyzer runs"
        columns={RUN_COLUMNS}
        rows={rows}
        rowKey={(row) => row.key}
        empty={<EmptyState compact title="No analyzer runs were recorded." />}
      />
    </Card>
  );
}
