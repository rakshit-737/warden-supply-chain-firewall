import type { Scan } from "../api/types";
import { booleanOrNull, isRecord, textOrNull } from "./values";

/**
 * Whether the machine-learning model ran for this scan: true or false when the scan records it, null
 * when it does not say (scans recorded before Warden X). The server stores ml_score = 0 when no model
 * ran, so a score of 0 on its own cannot tell "assessed as low risk" from "not assessed".
 *
 * explanation.ml.available decides when present; otherwise a recorded model_version is used (the
 * server records null there when no model was loaded).
 */
export function mlModelUsed(scan: Pick<Scan, "explanation" | "model_version">): boolean | null {
  const explanation = scan.explanation;
  const ml = isRecord(explanation) && isRecord(explanation.ml) ? explanation.ml : null;
  const available = ml ? booleanOrNull(ml.available) : null;
  if (available !== null) return available;
  if (scan.model_version === undefined) return null;
  return textOrNull(scan.model_version) !== null;
}
