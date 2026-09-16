import { useCallback, useRef, useState } from "react";
import { toApiError, type ApiError } from "../../api/client";
import { acknowledgeEvent } from "../../api/events";
import type { SecurityEvent } from "../../api/types";

interface Entry {
  status: "pending" | "saved";
  /** The optimistic record while pending; the server's response once saved. */
  event: SecurityEvent;
}

export type AckStatus = "idle" | "pending" | "saved";

export interface AckView {
  /** The event with any local acknowledgement applied. */
  event: SecurityEvent;
  /** idle: no acknowledgement from this page; pending: request in flight; saved: acknowledged here. */
  status: AckStatus;
}

export interface AckFailure {
  /** The event as it was before the failed attempt. */
  event: SecurityEvent;
  error: ApiError;
}

export interface Acknowledgements {
  view: (event: SecurityEvent) => AckView;
  acknowledge: (event: SecurityEvent) => Promise<void>;
  failure: AckFailure | null;
  dismissFailure: () => void;
  /** Text for a polite live region. */
  announcement: string;
}

function withAcknowledgement(event: SecurityEvent, from: SecurityEvent): SecurityEvent {
  return {
    ...event,
    acknowledged: true,
    acknowledged_by: from.acknowledged_by,
    acknowledged_at: from.acknowledged_at,
  };
}

/**
 * Optimistic acknowledgement: the event shows as acknowledged as soon as it is requested, and the
 * change is rolled back (with the server's reason) when the request fails. The server enforces
 * event:ack; the caller only offers the action to roles that hold it.
 */
export function useAcknowledgements(currentUserId: string | null): Acknowledgements {
  const [entries, setEntries] = useState<ReadonlyMap<string, Entry>>(() => new Map());
  const [failure, setFailure] = useState<AckFailure | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const inFlight = useRef(new Set<string>());

  const view = useCallback(
    (event: SecurityEvent): AckView => {
      const entry = entries.get(event.id);
      if (!entry) return { event, status: "idle" };
      if (entry.status === "pending") return { event: withAcknowledgement(event, entry.event), status: "pending" };
      // A refresh that started before the acknowledgement can still report it as open.
      return { event: event.acknowledged ? event : withAcknowledgement(event, entry.event), status: "saved" };
    },
    [entries],
  );

  const acknowledge = useCallback(
    async (event: SecurityEvent) => {
      if (event.acknowledged || inFlight.current.has(event.id)) return;
      inFlight.current.add(event.id);
      const optimistic: SecurityEvent = {
        ...event,
        acknowledged: true,
        acknowledged_by: currentUserId,
        acknowledged_at: new Date().toISOString(),
      };
      setEntries((previous) => new Map(previous).set(event.id, { status: "pending", event: optimistic }));
      setFailure((previous) => (previous?.event.id === event.id ? null : previous));
      setAnnouncement("");
      try {
        const saved = await acknowledgeEvent(event.id);
        setEntries((previous) => new Map(previous).set(event.id, { status: "saved", event: saved }));
        setAnnouncement(`Acknowledged: ${event.title}`);
      } catch (err) {
        setEntries((previous) => {
          const next = new Map(previous);
          next.delete(event.id);
          return next;
        });
        setFailure({ event, error: toApiError(err) });
      } finally {
        inFlight.current.delete(event.id);
      }
    },
    [currentUserId],
  );

  const dismissFailure = useCallback(() => setFailure(null), []);

  return { view, acknowledge, failure, dismissFailure, announcement };
}
