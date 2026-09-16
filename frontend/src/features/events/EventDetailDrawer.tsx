import type { ReactNode } from "react";
import { Link } from "react-router";
import type { SecurityEvent } from "../../api/types";
import { ErrorState } from "../../components/ErrorState";
import { KeyValueList } from "../../components/KeyValueList";
import { SeverityBadge } from "../../components/SeverityBadge";
import { revealInvisible } from "../../lib/text";
import { AckBadge, AckControl } from "./AckControl";
import { Drawer } from "./Drawer";
import { DrawerSection as Section } from "./DrawerSection";
import { eventTypeLabel, packageScansPath, scanPath } from "./eventLabels";
import { RelativeTime } from "./RelativeTime";
import type { ParamChanges } from "./searchParams";
import { StructuredDetails } from "./StructuredDetails";
import type { AckFailure, AckView } from "./useAcknowledgements";

export interface EventDetailDrawerProps {
  /** The selected event with local acknowledgement applied; null when closed. */
  view: AckView | null;
  now: number;
  currentUserId: string | null;
  canAcknowledge: boolean;
  failure: AckFailure | null;
  onAcknowledge: (event: SecurityEvent) => void;
  onFilter: (changes: ParamChanges) => void;
  onClose: () => void;
  fallbackFocus?: () => HTMLElement | null;
}

function userText(userId: string | null, currentUserId: string | null): ReactNode {
  if (userId === null) return null;
  if (userId === currentUserId) {
    return (
      <span>
        You <span className="font-mono text-xs text-ink-muted">{userId}</span>
      </span>
    );
  }
  return <span className="font-mono text-[0.8125rem]">{userId}</span>;
}

const LINK = "text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent";

export function EventDetailDrawer({
  view,
  now,
  currentUserId,
  canAcknowledge,
  failure,
  onAcknowledge,
  onFilter,
  onClose,
  fallbackFocus,
}: EventDetailDrawerProps) {
  if (!view) return null;
  const { event, status } = view;
  const pkg = event.package;
  const projectId = event.project_id;
  const scanId = event.scan_id;
  const failureHere = failure !== null && failure.event.id === event.id ? failure : null;
  const showAction = canAcknowledge && (status !== "idle" || !event.acknowledged);

  return (
    <Drawer
      open
      title={revealInvisible(event.title)}
      description={
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <SeverityBadge value={event.severity} />
          <span>{eventTypeLabel(event.type)}</span>
        </span>
      }
      onClose={onClose}
      fallbackFocus={fallbackFocus}
      footer={
        showAction || failureHere ? (
          <div className="flex flex-col items-start gap-3">
            {failureHere && <ErrorState title="The event was not acknowledged" error={failureHere.error} />}
            {showAction && (
              <AckControl
                size="md"
                view={view}
                canAcknowledge={canAcknowledge}
                subject={`event ${event.title}`}
                onAcknowledge={() => onAcknowledge(event)}
              />
            )}
          </div>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-6">
        <Section title="Event">
          <KeyValueList
            items={[
              {
                term: "Type",
                value: (
                  <span className="flex flex-wrap items-baseline gap-x-2">
                    {eventTypeLabel(event.type)}
                    <code className="font-mono text-xs text-ink-muted">{revealInvisible(event.type)}</code>
                  </span>
                ),
              },
              { term: "Severity", value: <SeverityBadge value={event.severity} /> },
              { term: "Recorded", value: <RelativeTime value={event.created_at} now={now} layout="inline" /> },
              { term: "Package", value: pkg ? revealInvisible(pkg) : null, mono: true },
              { term: "Version", value: event.version ? revealInvisible(event.version) : null, mono: true },
              { term: "Project ID", value: projectId, mono: true },
              { term: "Scan ID", value: scanId, mono: true },
              { term: "Event ID", value: event.id, mono: true },
            ]}
          />
        </Section>

        <Section title="Acknowledgement">
          <KeyValueList
            emptyText="Not yet"
            items={[
              { term: "Status", value: status === "pending" ? "Acknowledging" : <AckBadge acknowledged={event.acknowledged} /> },
              { term: "By", value: event.acknowledged ? userText(event.acknowledged_by, currentUserId) : null },
              {
                term: "At",
                value: event.acknowledged_at ? (
                  <RelativeTime value={event.acknowledged_at} now={Math.max(now, Date.parse(event.acknowledged_at) || 0)} layout="inline" />
                ) : null,
              },
            ]}
          />
          {!canAcknowledge && !event.acknowledged && (
            <p className="text-xs text-ink-muted">Acknowledging events requires the event:ack permission (admin or security analyst).</p>
          )}
        </Section>

        {(scanId || pkg || projectId) && (
          <Section title="Related">
            <ul className="flex flex-col gap-1.5">
              {scanId && (
                <li>
                  <Link to={scanPath(scanId)} className={LINK}>
                    Open the scan
                  </Link>
                </li>
              )}
              {pkg && (
                <li>
                  <Link to={packageScansPath(pkg)} className={LINK}>
                    Scans of <span className="font-mono">{revealInvisible(pkg)}</span>
                  </Link>
                </li>
              )}
              {pkg && (
                <li>
                  <button type="button" className={`text-left ${LINK}`} onClick={() => onFilter({ package: pkg, offset: null })}>
                    Show only events for <span className="font-mono">{revealInvisible(pkg)}</span>
                  </button>
                </li>
              )}
              {projectId && (
                <li>
                  <button type="button" className={`text-left ${LINK}`} onClick={() => onFilter({ project_id: projectId, offset: null })}>
                    Show only events for this project
                  </button>
                </li>
              )}
            </ul>
          </Section>
        )}

        <Section title="Details">
          <p className="text-xs text-ink-muted">
            Recorded by the server after redacting secret-shaped values. Shown exactly as text; nothing here is a link.
          </p>
          <StructuredDetails value={event.details} emptyText="No details were recorded for this event." rawLabel="Raw details (JSON)" />
        </Section>
      </div>
    </Drawer>
  );
}
