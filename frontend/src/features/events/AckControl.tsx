import type { AckView } from "./useAcknowledgements";

function CheckGlyph() {
  return (
    <svg aria-hidden="true" viewBox="0 0 12 12" className="h-3 w-3 shrink-0">
      <path d="M2 6.5 4.8 9 10 3" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function OpenGlyph() {
  return (
    <svg aria-hidden="true" viewBox="0 0 12 12" className="h-3 w-3 shrink-0">
      <circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

/** Acknowledgement state as text plus a shape (ring = open, tick = acknowledged). */
export function AckBadge({ acknowledged }: { acknowledged: boolean }) {
  return acknowledged ? (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs text-ink-secondary">
      <CheckGlyph />
      Acknowledged
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-semibold text-ink">
      <OpenGlyph />
      Unacknowledged
    </span>
  );
}

export interface AckControlProps {
  view: AckView;
  /** Whether the role holds event:ack (UI affordance; the server enforces it). */
  canAcknowledge: boolean;
  onAcknowledge: () => void;
  /** Names the event for assistive technology, e.g. `event "Package blocked"`. */
  subject: string;
  size?: "sm" | "md";
}

/**
 * Acknowledge button for roles with event:ack, otherwise the state as text. Once clicked the same
 * button element stays in place (aria-disabled, relabelled) so keyboard focus is not lost while the
 * request runs, when it succeeds, or when it is rolled back.
 */
export function AckControl({ view, canAcknowledge, onAcknowledge, subject, size = "sm" }: AckControlProps) {
  const { event, status } = view;
  if (!canAcknowledge || (status === "idle" && event.acknowledged)) return <AckBadge acknowledged={event.acknowledged} />;
  const busy = status !== "idle";
  const label = status === "pending" ? "Acknowledging" : status === "saved" ? "Acknowledged" : "Acknowledge";
  return (
    <button
      type="button"
      className={size === "sm" ? "btn-secondary h-7 px-2" : "btn-primary"}
      aria-disabled={busy || undefined}
      onClick={() => {
        if (!busy) onAcknowledge();
      }}
    >
      {busy && <CheckGlyph />}
      {/* The separating space stays outside the hidden span so the accessible name keeps it. */}
      {label} <span className="sr-only">{subject}</span>
    </button>
  );
}
