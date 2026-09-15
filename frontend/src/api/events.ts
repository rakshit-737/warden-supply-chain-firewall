import { api, cleanParams, pathSegment, type RequestOptions } from "./client";
import type { ListEventsParams, Page, SecurityEvent } from "./types";

export async function listEvents(params: ListEventsParams = {}, opts: RequestOptions = {}): Promise<Page<SecurityEvent>> {
  const r = await api.get<Page<SecurityEvent>>("/events", { params: cleanParams(params), signal: opts.signal });
  return r.data;
}

/** Requires event:ack on the server. */
export async function acknowledgeEvent(id: string): Promise<SecurityEvent> {
  const r = await api.post<SecurityEvent>(`/events/${pathSegment(id)}/ack`);
  return r.data;
}
