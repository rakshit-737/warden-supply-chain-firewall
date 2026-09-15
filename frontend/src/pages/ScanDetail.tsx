import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router";
import { getScan } from "../api/scans";
import type { AnalyzerRun, AttackChain, Finding, Scan, Severity, Vulnerability } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import type { LinkedFinding } from "../components/AttackChainView";
import { Card } from "../components/Card";
import { DecisionBadge } from "../components/DecisionBadge";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { RiskGauge } from "../components/RiskGauge";
import { SeverityBadge } from "../components/SeverityBadge";
import { LoadingBlock } from "../components/Skeleton";
import { Tabs, type TabItem } from "../components/Tabs";
import { useApiQuery } from "../hooks/useApiQuery";
import { findingAnchorId } from "../lib/findings";
import { compareFindings } from "../lib/risk";
import { isRecord, pickOption, recordArray, textOrNull } from "../lib/values";
import {
  AnalyzerRunsPanel,
  AttackChainsPanel,
  FindingsPanel,
  PolicyOutcome,
  ProvenancePanel,
  ReportExport,
  RiskPanel,
  ScanMeta,
  ScoresList,
  VulnerabilitiesPanel,
} from "./scan/panels";

const BACK = { to: "/scans", label: "Back to scans" };
const TAB_IDS = ["findings", "risk", "chains", "vulnerabilities", "provenance", "analyzers"] as const;

function ScanReport({ scan }: { scan: Scan }) {
  const canExport = usePermission(PERMISSIONS.REPORT_READ);
  // The open tab lives in the URL (?tab=) so a link can point straight at, say, a scan's vulnerabilities.
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = pickOption(TAB_IDS, searchParams.get("tab")) ?? "findings";
  const selectTab = useCallback(
    (id: string) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          if (id === "findings") next.delete("tab");
          else next.set("tab", id);
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [focus, setFocus] = useState<{ id: string; seq: number } | null>(null);

  const findings = useMemo(() => (recordArray<Finding>(scan.signals) ?? []).sort(compareFindings), [scan.signals]);
  const linked = useMemo(() => {
    const map = new Map<string, LinkedFinding>();
    for (const finding of findings) {
      const id = textOrNull(finding.finding_id);
      if (id) map.set(id, { code: finding.code, title: finding.title });
    }
    return map;
  }, [findings]);

  // Bring a finding chosen from an attack chain or policy reason into view.
  useEffect(() => {
    if (!focus || tab !== "findings") return;
    const target = document.getElementById(findingAnchorId(focus.id));
    if (!target) return;
    if (typeof target.scrollIntoView === "function") target.scrollIntoView({ block: "start" });
    target.focus({ preventScroll: true });
  }, [focus, tab]);

  function showFinding(findingId: string) {
    selectTab("findings");
    setSeverity("all");
    setFocus((previous) => ({ id: findingId, seq: (previous?.seq ?? 0) + 1 }));
  }

  const chains = recordArray<AttackChain>(scan.attack_chains);
  const vulnerabilities = recordArray<Vulnerability>(scan.vulnerabilities);
  const runs = recordArray<AnalyzerRun>(scan.analyzer_runs);
  const provenance = isRecord(scan.provenance) ? scan.provenance : null;
  const intel = isRecord(scan.intel_status) ? scan.intel_status : null;
  const predatesWardenX =
    !isRecord(scan.risk) && chains === null && vulnerabilities === null && runs === null && provenance === null;

  const tabs: TabItem[] = [
    {
      id: "findings",
      label: "Findings",
      count: findings.length,
      content: <FindingsPanel findings={findings} severity={severity} onSeverityChange={setSeverity} />,
    },
    { id: "risk", label: "Risk breakdown", content: <RiskPanel scan={scan} /> },
    {
      id: "chains",
      label: "Attack chains",
      count: chains?.length,
      content: <AttackChainsPanel chains={chains} findings={linked} onFindingClick={showFinding} />,
    },
    {
      id: "vulnerabilities",
      label: "Vulnerabilities",
      count: vulnerabilities?.length,
      content: <VulnerabilitiesPanel vulnerabilities={vulnerabilities} intel={intel} />,
    },
    { id: "provenance", label: "Provenance", content: <ProvenancePanel provenance={provenance} /> },
    { id: "analyzers", label: "Analyzer runs", count: runs?.length, content: <AnalyzerRunsPanel runs={runs} /> },
  ];

  return (
    <>
      <PageHeader
        title={`${scan.package_name} ${scan.version}`}
        heading={
          <span className="break-all font-mono text-xl font-medium sm:text-2xl">
            {scan.package_name}
            <span className="text-ink-muted">=={scan.version}</span>
          </span>
        }
        back={BACK}
        meta={<ScanMeta scan={scan} />}
        actions={canExport ? <ReportExport scan={scan} /> : undefined}
      />
      <div className="flex flex-col gap-4">
        <div className="grid gap-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,4fr)]">
          <Card title="Verdict">
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
                <DecisionBadge value={scan.decision} size="lg" />
                <SeverityBadge value={scan.severity} />
              </div>
              <RiskGauge score={scan.risk_score} size="lg" label="Final risk score" />
              <PolicyOutcome scan={scan} findings={linked} onFindingClick={showFinding} />
            </div>
          </Card>
          <Card title="Scores">
            <ScoresList scan={scan} />
          </Card>
        </div>
        {predatesWardenX && (
          <p className="rounded-r-md border-l-2 border-line-strong bg-panel px-4 py-2.5 text-ink-secondary">
            This scan was recorded without Warden X analysis data, so risk dimensions, attack chains, vulnerability
            intelligence, provenance and analyzer runs are not available for it.
          </p>
        )}
        <Tabs label="Scan details" tabs={tabs} value={tab} onChange={selectTab} />
      </div>
    </>
  );
}

export default function ScanDetail() {
  const { id = "" } = useParams();
  const query = useApiQuery(id ? `scan:${id}` : null, (signal) => getScan(id, { signal }));

  if (query.data) return <ScanReport key={query.data.id} scan={query.data} />;
  return (
    <>
      <PageHeader title="Scan" back={BACK} />
      {query.error ? (
        <ErrorState error={query.error} onRetry={query.reload} title="This scan could not be loaded" />
      ) : (
        <LoadingBlock label="Loading scan" rows={8} />
      )}
    </>
  );
}
