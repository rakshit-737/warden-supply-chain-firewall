import type { AuditEvent } from "../../api/types";
import { KeyValueList } from "../../components/KeyValueList";
import { revealInvisible } from "../../lib/text";
import { numberOrNull } from "../../lib/values";
import { Drawer } from "../events/Drawer";
import { DrawerSection } from "../events/DrawerSection";
import { RelativeTime } from "../events/RelativeTime";
import type { ParamChanges } from "../events/searchParams";
import { StructuredDetails } from "../events/StructuredDetails";

export interface AuditDetailDrawerProps {
  entry: AuditEvent | null;
  now: number;
  currentUserId: string | null;
  onFilter: (changes: ParamChanges) => void;
  onClose: () => void;
  fallbackFocus?: () => HTMLElement | null;
}

const FILTER_BUTTON = "text-left text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent";

export function AuditDetailDrawer({ entry, now, currentUserId, onFilter, onClose, fallbackFocus }: AuditDetailDrawerProps) {
  if (!entry) return null;
  const seq = numberOrNull(entry.seq);
  const actorId = entry.actor_id;
  const targetType = entry.target_type;
  const action = entry.action;

  return (
    <Drawer
      open
      title={<span className="break-all font-mono text-lg">{revealInvisible(action)}</span>}
      description={seq === null ? "Not part of the hash chain" : `Audit event, seq ${seq}`}
      onClose={onClose}
      fallbackFocus={fallbackFocus}
    >
      <div className="flex flex-col gap-6">
        <DrawerSection title="Record">
          <KeyValueList
            items={[
              { term: "Action", value: revealInvisible(action), mono: true },
              { term: "Recorded", value: <RelativeTime value={entry.created_at} now={now} layout="inline" /> },
              {
                term: "Actor",
                value:
                  actorId === null ? (
                    "No signed-in user (for example a failed sign-in)"
                  ) : (
                    <span className="flex flex-col">
                      {actorId === currentUserId && <span>You</span>}
                      <code className="break-all font-mono text-[0.8125rem]">{actorId}</code>
                    </span>
                  ),
              },
              { term: "Target type", value: targetType ? revealInvisible(targetType) : null, mono: true },
              { term: "Target ID", value: entry.target_id ? revealInvisible(entry.target_id) : null, mono: true },
              { term: "Request ID", value: entry.request_id ? revealInvisible(entry.request_id) : null, mono: true },
              { term: "Event ID", value: entry.id, mono: true },
            ]}
          />
        </DrawerSection>

        <DrawerSection title="Hash chain">
          <KeyValueList
            items={[
              { term: "Seq", value: seq === null ? null : String(seq), mono: true },
              {
                term: "Previous hash",
                value: entry.prev_hash ? <code className="break-all font-mono text-xs">{entry.prev_hash}</code> : null,
              },
              {
                term: "Event hash",
                value: entry.event_hash ? <code className="break-all font-mono text-xs">{entry.event_hash}</code> : null,
              },
            ]}
          />
          <p className="text-xs text-ink-muted">
            These are the stored values. Use Verify integrity to recompute them; a stored hash on its own proves nothing.
          </p>
        </DrawerSection>

        <DrawerSection title="Show similar entries">
          <ul className="flex flex-col gap-1.5">
            <li>
              <button type="button" className={FILTER_BUTTON} onClick={() => onFilter({ action, offset: null })}>
                Only <span className="font-mono">{revealInvisible(action)}</span> entries
              </button>
            </li>
            {actorId && (
              <li>
                <button type="button" className={FILTER_BUTTON} onClick={() => onFilter({ actor_id: actorId, offset: null })}>
                  Only entries by this actor
                </button>
              </li>
            )}
            {targetType && (
              <li>
                <button type="button" className={FILTER_BUTTON} onClick={() => onFilter({ target_type: targetType, offset: null })}>
                  Only entries with target type <span className="font-mono">{revealInvisible(targetType)}</span>
                </button>
              </li>
            )}
          </ul>
        </DrawerSection>

        <DrawerSection title="Metadata">
          <p className="text-xs text-ink-muted">
            Recorded by the server after redacting secret-shaped values. Shown exactly as text; nothing here is a link.
          </p>
          <StructuredDetails value={entry.metadata} emptyText="No metadata was recorded." rawLabel="Raw metadata (JSON)" />
        </DrawerSection>
      </div>
    </Drawer>
  );
}
