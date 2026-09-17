import { useId } from "react";
import type { AttackChain, AttackChainStep } from "../api/types";
import { findingAnchorId } from "../lib/findings";
import { humanize } from "../lib/format";
import { attackTechniqueUrl } from "../lib/url";
import { numberOrNull, stringArray, textOrNull } from "../lib/values";
import { ConfidencePill } from "./ConfidencePill";
import { EmptyState } from "./EmptyState";
import { ExternalLink } from "./ExternalLink";
import { SeverityBadge } from "./SeverityBadge";

export interface LinkedFinding {
  code: string;
  title?: string | null;
}

export interface AttackChainViewProps {
  chains: readonly AttackChain[];
  /** finding_id -> finding summary, used to label linked findings. */
  findings?: ReadonlyMap<string, LinkedFinding>;
  /** Called when a linked finding is chosen; without it the link jumps to the finding's anchor. */
  onFindingClick?: (findingId: string) => void;
}

/** Steps by their `order` field; steps without one keep their position in the array. */
function orderedSteps(steps: unknown): AttackChainStep[] {
  if (!Array.isArray(steps)) return [];
  return steps
    .filter((step): step is AttackChainStep => typeof step === "object" && step !== null)
    .map((step, index) => ({ step, index, order: numberOrNull(step.order) ?? index + 1 }))
    .sort((a, b) => a.order - b.order || a.index - b.index)
    .map(({ step }) => step);
}

function ChainCard({
  chain,
  index,
  findings,
  onFindingClick,
}: {
  chain: AttackChain;
  index: number;
  findings?: ReadonlyMap<string, LinkedFinding>;
  onFindingClick?: (findingId: string) => void;
}) {
  const headingId = useId();
  const steps = orderedSteps(chain.steps);
  const title = textOrNull(chain.title) ?? `Attack chain ${index + 1}`;
  return (
    <article aria-labelledby={headingId} className="rounded-md border border-line bg-panel">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-line px-4 py-2.5">
        <h3 id={headingId} className="wrap-break-word font-semibold text-ink">
          {title}
        </h3>
        {chain.severity && <SeverityBadge value={chain.severity} />}
        {typeof chain.confidence === "number" && <ConfidencePill value={chain.confidence} />}
      </header>
      {textOrNull(chain.summary) && <p className="wrap-break-word px-4 pt-3 text-ink-secondary">{chain.summary}</p>}
      {steps.length === 0 ? (
        <div className="px-4">
          <EmptyState compact title="No steps were recorded for this chain." />
        </div>
      ) : (
        <ol aria-label={`${title} steps`} className="px-4 py-3">
          {steps.map((step, position) => {
            const techniqueId = textOrNull(step.technique_id);
            const techniqueUrl = techniqueId ? attackTechniqueUrl(techniqueId) : null;
            const findingIds = stringArray(step.finding_ids);
            const isLast = position === steps.length - 1;
            return (
              <li key={`${position}-${techniqueId ?? "step"}`} className="grid grid-cols-[1.5rem_minmax(0,1fr)] gap-x-3">
                <span aria-hidden="true" className="relative flex justify-center">
                  {!isLast && <span className="absolute bottom-0 top-7 w-px bg-line" />}
                  <span className="relative mt-0.5 grid h-6 w-6 place-items-center rounded-full border border-line-strong bg-raised text-2xs font-semibold tabular-nums text-ink">
                    {position + 1}
                  </span>
                </span>
                <div className={`min-w-0 pt-0.5 ${isLast ? "" : "pb-4"}`}>
                  <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                    {techniqueId === null ? (
                      <span className="text-xs text-ink-muted">Technique not mapped</span>
                    ) : techniqueUrl ? (
                      <ExternalLink href={techniqueUrl} className="font-mono text-xs">
                        {techniqueId}
                      </ExternalLink>
                    ) : (
                      <code className="break-all font-mono text-xs text-ink-secondary">{techniqueId}</code>
                    )}
                    {textOrNull(step.technique_name) && (
                      <span className="wrap-break-word font-medium text-ink">{step.technique_name}</span>
                    )}
                    {textOrNull(step.tactic) && (
                      <span className="rounded-sm bg-raised px-1.5 py-0.5 text-2xs text-ink-secondary">
                        {humanize(step.tactic ?? "")}
                      </span>
                    )}
                  </div>
                  {textOrNull(step.description) && (
                    <p className="mt-1 wrap-break-word text-ink-secondary">{step.description}</p>
                  )}
                  {findingIds.length > 0 && (
                    <ul aria-label="Linked findings" className="mt-1.5 flex flex-wrap gap-1.5">
                      {findingIds.map((findingId) => {
                        const linked = findings?.get(findingId);
                        return (
                          <li key={findingId}>
                            <a
                              href={`#${findingAnchorId(findingId)}`}
                              onClick={(event) => {
                                if (!onFindingClick) return;
                                event.preventDefault();
                                onFindingClick(findingId);
                              }}
                              className="inline-flex items-center rounded-sm border border-line px-1.5 py-0.5 font-mono text-2xs text-ink-secondary hover:border-accent hover:text-ink"
                            >
                              {linked ? linked.code : findingId}
                            </a>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </article>
  );
}

/** Correlated attack chains: ordered steps with ATT&CK technique, tactic and the findings behind each step. */
export function AttackChainView({ chains, findings, onFindingClick }: AttackChainViewProps) {
  if (chains.length === 0) return <EmptyState compact title="No attack chains were correlated." />;
  return (
    <div className="flex flex-col gap-3">
      {chains.map((chain, index) => (
        <ChainCard
          key={chain.id ?? `chain-${index}`}
          chain={chain}
          index={index}
          findings={findings}
          onFindingClick={onFindingClick}
        />
      ))}
    </div>
  );
}
