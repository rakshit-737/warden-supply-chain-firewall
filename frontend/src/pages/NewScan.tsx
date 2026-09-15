import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { CLIENT_TIMEOUT_CODE, toApiError, type ApiError } from "../api/client";
import { createScan } from "../api/scans";
import { ENVIRONMENTS, type Environment, type Scan } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { DecisionBadge } from "../components/DecisionBadge";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { KeyValueList } from "../components/KeyValueList";
import { PageHeader } from "../components/PageHeader";
import { RiskGauge } from "../components/RiskGauge";
import { SelectField } from "../components/SelectField";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatDuration, humanize } from "../lib/format";
import { mlModelUsed } from "../lib/scan";
import { numberOrNull, pickOption, stringArray } from "../lib/values";

const BACK = { to: "/scans", label: "Back to scans" };

/**
 * The console (client timeout) or the web server (504) stopped waiting. The scan request itself was
 * accepted, so the server may still finish the analysis and record it.
 */
function isAbandonedWait(error: ApiError): boolean {
  return error.code === CLIENT_TIMEOUT_CODE || error.status === 504;
}

function ScanResult({ scan }: { scan: Scan }) {
  const rules = stringArray(scan.matched_policy_rules);
  const modelUsed = mlModelUsed(scan);
  return (
    <Card
      title={
        <span className="break-all font-mono">
          {scan.package_name}
          <span className="text-ink-muted">=={scan.version}</span>
        </span>
      }
      description="Scan complete"
      actions={
        <Link to={`/scans/${encodeURIComponent(scan.id)}`} className="btn-primary">
          Open scan details
        </Link>
      }
    >
      <div className="grid gap-5 md:grid-cols-2">
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-4">
            <DecisionBadge value={scan.decision} size="lg" />
            <SeverityBadge value={scan.severity} />
          </div>
          <RiskGauge score={scan.risk_score} size="lg" label="Final risk score" />
        </div>
        <KeyValueList
          items={[
            { term: "Rule score", value: numberOrNull(scan.rule_score) },
            // The server records 0 when no model ran; do not present that as a score.
            { term: "ML score", value: modelUsed === false ? "Model not available" : numberOrNull(scan.ml_score) },
            { term: "Findings", value: Array.isArray(scan.signals) ? scan.signals.length : null },
            { term: "Duration", value: formatDuration(scan.duration_ms) },
            {
              term: "Matched policy rules",
              value:
                rules.length > 0 ? (
                  <span className="flex flex-wrap gap-1.5">
                    {rules.map((rule) => (
                      <code key={rule} className="break-all rounded bg-raised px-1.5 py-0.5 font-mono text-2xs">
                        {rule}
                      </code>
                    ))}
                  </span>
                ) : (
                  "None"
                ),
            },
          ]}
        />
      </div>
    </Card>
  );
}

export default function NewScan() {
  const canScan = usePermission(PERMISSIONS.SCAN_CREATE);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [environment, setEnvironment] = useState<Environment>("production");
  const [pending, setPending] = useState<string | null>(null);
  const [submittedName, setSubmittedName] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<Scan | null>(null);

  if (!canScan) {
    return (
      <>
        <PageHeader title="New scan" back={BACK} />
        <EmptyState
          title="Your role can review scans but not start them."
          description="Starting a scan needs the scan:create permission, held by the admin, security analyst and developer roles."
          action={
            <Link to="/scans" className="btn-secondary">
              View scans
            </Link>
          }
        />
      </>
    );
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const packageName = name.trim();
    if (!packageName || pending !== null) return;
    const requestedVersion = version.trim();
    setPending(requestedVersion ? `${packageName}==${requestedVersion}` : packageName);
    setSubmittedName(packageName);
    setError(null);
    setResult(null);
    try {
      setResult(await createScan({ name: packageName, version: requestedVersion || null, environment }));
    } catch (err) {
      setError(toApiError(err));
    } finally {
      setPending(null);
    }
  }

  return (
    <>
      <PageHeader
        title="New scan"
        back={BACK}
        description="Analyse one PyPI release and evaluate it against the active policy of an environment."
      />
      <div className="flex flex-col gap-4">
        <Card title="Package">
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4 sm:grid-cols-2 lg:grid-cols-[minmax(0,1fr)_12rem_12rem_auto] lg:items-end"
          >
            <div>
              <label htmlFor="scan-name" className="label">
                Package name
              </label>
              <input
                id="scan-name"
                className="input font-mono"
                required
                maxLength={214}
                autoComplete="off"
                spellCheck={false}
                placeholder="requests"
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </div>
            <div>
              <label htmlFor="scan-version" className="label">
                Version
              </label>
              <input
                id="scan-version"
                className="input font-mono"
                maxLength={64}
                autoComplete="off"
                spellCheck={false}
                placeholder="Latest release"
                value={version}
                onChange={(event) => setVersion(event.target.value)}
              />
            </div>
            <SelectField
              id="scan-environment"
              label="Policy environment"
              value={environment}
              options={ENVIRONMENTS.map((env) => ({ value: env, label: humanize(env) }))}
              onChange={(value) => setEnvironment(pickOption(ENVIRONMENTS, value) ?? "production")}
            />
            <button type="submit" className="btn-primary" disabled={pending !== null || name.trim() === ""}>
              {pending !== null ? "Scanning" : "Start scan"}
            </button>
          </form>
          <p className="mt-3 text-xs text-ink-muted">
            Warden downloads the release from PyPI and inspects it without installing or running it.
          </p>
        </Card>

        {pending !== null && (
          <div role="status" className="flex items-center gap-3 rounded-md border border-line bg-panel px-4 py-3">
            <span
              aria-hidden="true"
              className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-line-strong border-t-accent"
            />
            <span>
              Analysing <code className="break-all font-mono">{pending}</code>. Large releases can take a few minutes.
            </span>
          </div>
        )}
        {error &&
          (isAbandonedWait(error) ? (
            <div className="flex flex-col items-start gap-2">
              <ErrorState
                title="The scan result did not arrive in time"
                error={{
                  ...error,
                  message:
                    "Warden stopped waiting, but the server may still finish this scan and record it. Look for it in the scan list before starting the same scan again.",
                }}
              />
              <Link to={`/scans?q=${encodeURIComponent(submittedName)}`} className="btn-secondary">
                Check Scans for {submittedName}
              </Link>
            </div>
          ) : (
            <ErrorState error={error} title="The scan did not complete" />
          ))}
        {result && <ScanResult scan={result} />}
      </div>
    </>
  );
}
