import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { ListEventsParams, Page, SecurityEvent } from "./types";

/** Requires event:read. Newest first. */
export async function listEvents(params: ListEventsParams = {}, opts: RequestOptions = {}): Promise<Page<SecurityEvent>> {
  const r = await api.get<Page<SecurityEvent>>("/events", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

/**
 * Requires event:ack on the server. Idempotent: acknowledging an acknowledged event returns it
 * unchanged, keeping the original acknowledger.
 */
export async function acknowledgeEvent(id: string, opts: RequestOptions = {}): Promise<SecurityEvent> {
  const r = await api.post<SecurityEvent>(`/events/${pathSegment(id)}/ack`, undefined, { signal: opts.signal });
  return r.data;
}
