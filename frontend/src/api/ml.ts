import { api, type RequestOptions } from "./client";
import type { ModelDrift, ModelInfo } from "./types";

/** Requires ml:read. */
export async function getModelInfo(opts: RequestOptions = {}): Promise<ModelInfo> {
  const r = await api.get<ModelInfo>("/ml/model", { signal: opts.signal });
  return r.data;
}

/** Requires ml:read. */
export async function getModelDrift(opts: RequestOptions = {}): Promise<ModelDrift> {
  const r = await api.get<ModelDrift>("/ml/drift", { signal: opts.signal });
  return r.data;
}
