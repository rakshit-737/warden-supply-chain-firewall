import { useId, useState } from "react";
import type { Finding } from "../api/types";
import { findingAnchorId, formatLocation } from "../lib/findings";
import { humanize } from "../lib/format";
import { attackTechniqueUrl, cweUrl } from "../lib/url";
import { isRecord, numberOrNull, stringArray, textOrNull } from "../lib/values";
import { CodeBlock } from "./CodeBlock";
import { ConfidencePill } from "./ConfidencePill";
import { ExternalLink } from "./ExternalLink";
import { SeverityBadge } from "./SeverityBadge";

export interface FindingCardProps {
  finding: Finding;
  defaultExpanded?: boolean;
}

function MappingChip({ id, href }: { id: string; href: string | null }) {
  const chip = "inline-flex rounded border border-line px-1.5 py-0.5 font-mono text-2xs";
  return href ? (
    <ExternalLink href={href} plain className={`${chip} text-ink-secondary hover:border-accent hover:text-ink`}>
      {id}
    </ExternalLink>
  ) : (
    <span className={`${chip} text-ink-muted`}>{id}</span>
  );
}

/**
 * One finding: severity, code, confidence, category, location (file:line only when the analyzer
 * reported it), CWE and ATT&CK mappings, remediation, references and collapsible evidence. All
 * text is rendered as text; evidence goes through CodeBlock.
 */
export function FindingCard({ finding, defaultExpanded = false }: FindingCardProps) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const titleId = useId();
  const evidenceId = useId();

  const explicitTitle = textOrNull(finding.title);
  const message = textOrNull(finding.message);
  const title = explicitTitle ?? message ?? finding.code;
  const location = formatLocation(finding.location);
  const cwe = stringArray(finding.cwe);
  const attack = stringArray(finding.attack);
  const references = stringArray(finding.references);
  const evidence = isRecord(finding.evidence) ? finding.evidence : {};
  const hasEvidence = Object.keys(evidence).length > 0;
  const snippet = textOrNull(finding.location?.snippet);
  const weight = numberOrNull(finding.weight);
  const analyzer = textOrNull(finding.analyzer);
  const findingId = textOrNull(finding.finding_id);

  return (
    <article
      id={findingId ? findingAnchorId(findingId) : undefined}
      aria-labelledby={titleId}
      tabIndex={-1}
      data-severity={finding.severity}
      className="scroll-mt-4 rounded-md border border-line bg-panel focus-visible:outline-offset-0"
    >
      <div className="flex flex-col gap-2 px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <SeverityBadge value={finding.severity} />
          <code className="break-all rounded bg-raised px-1.5 py-0.5 font-mono text-2xs text-ink">{finding.code}</code>
          {textOrNull(finding.category) && (
            <span className="text-xs text-ink-secondary">{humanize(finding.category ?? "")}</span>
          )}
          <span className="sm:ml-auto">
            <ConfidencePill value={finding.confidence} />
          </span>
        </div>

        <h3 id={titleId} className="break-words font-semibold text-ink">
          {title}
        </h3>
        {explicitTitle && message && message !== explicitTitle && (
          <p className="break-words text-ink-secondary">{message}</p>
        )}

        <dl className="flex flex-wrap gap-x-5 gap-y-1 text-xs">
          {location && (
            <div className="flex min-w-0 gap-1.5">
              <dt className="text-ink-muted">Location</dt>
              <dd className="break-all font-mono text-ink">{location}</dd>
            </div>
          )}
          {analyzer && (
            <div className="flex gap-1.5">
              <dt className="text-ink-muted">Analyzer</dt>
              <dd className="text-ink-secondary">
                {analyzer}
                {textOrNull(finding.analyzer_version) ? ` ${finding.analyzer_version}` : ""}
              </dd>
            </div>
          )}
          {textOrNull(finding.capability) && (
            <div className="flex gap-1.5">
              <dt className="text-ink-muted">Capability</dt>
              <dd className="font-mono text-ink-secondary">{finding.capability}</dd>
            </div>
          )}
          <div className="flex gap-1.5">
            <dt className="text-ink-muted">Weight</dt>
            <dd className="tabular-nums text-ink-secondary">
              {weight === null ? "Not recorded" : Math.round(weight * 100) / 100}
            </dd>
          </div>
        </dl>

        {(cwe.length > 0 || attack.length > 0) && (
          <ul aria-label="CWE and ATT&CK mappings" className="flex flex-wrap gap-1.5">
            {cwe.map((id) => (
              <li key={`cwe-${id}`}>
                <MappingChip id={id} href={cweUrl(id)} />
              </li>
            ))}
            {attack.map((id) => (
              <li key={`attack-${id}`}>
                <MappingChip id={id} href={attackTechniqueUrl(id)} />
              </li>
            ))}
          </ul>
        )}

        {textOrNull(finding.remediation) && (
          <div className="rounded-r border-l-2 border-accent bg-sunken px-3 py-2">
            <h4 className="text-xs font-semibold text-ink">Remediation</h4>
            <p className="mt-0.5 whitespace-pre-line break-words text-ink-secondary">{finding.remediation}</p>
          </div>
        )}

        {references.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-ink">References</h4>
            <ul className="mt-0.5 flex flex-col gap-0.5 text-xs">
              {references.map((reference) => (
                <li key={reference}>
                  <ExternalLink href={reference} />
                </li>
              ))}
            </ul>
          </div>
        )}

        {(hasEvidence || snippet) && (
          <div>
            <button
              type="button"
              aria-expanded={expanded}
              aria-controls={evidenceId}
              onClick={() => setExpanded((open) => !open)}
              className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
            >
              <svg
                aria-hidden="true"
                viewBox="0 0 12 12"
                className={`h-3 w-3 fill-current transition-transform ${expanded ? "rotate-90" : ""}`}
              >
                <path d="M4 2.5 8.5 6 4 9.5Z" />
              </svg>
              {expanded ? "Hide evidence" : "Show evidence"}
            </button>
            <div id={evidenceId} hidden={!expanded} className="mt-2 flex flex-col gap-2">
              {expanded && snippet && <CodeBlock label="Snippet" value={snippet} />}
              {expanded && hasEvidence && <CodeBlock label="Evidence" value={evidence} />}
            </div>
          </div>
        )}
      </div>
    </article>
  );
}
