import type { AuditVerifyResult } from "../../api/types";
import { numberOrNull, textOrNull } from "../../lib/values";

export type IntegrityKind = "intact" | "empty" | "broken" | "unlocated";

export interface IntegrityVerdict {
  kind: IntegrityKind;
  headline: string;
  summary: string;
  ok: boolean;
  checked: number;
  brokenSeq: number | null;
  reason: string | null;
  headSeq: number | null;
  headHash: string | null;
  verifiedAt: string | null;
}

const integerFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });

/** Exact whole number with grouping (never compacted: audit counts must be exact). */
export function formatInteger(value: number): string {
  return integerFormat.format(value);
}

function events(count: number): string {
  return `${formatInteger(count)} ${count === 1 ? "event" : "events"}`;
}

/**
 * Plain-language reading of GET /audit/verify. Only `ok === true` counts as intact; anything else
 * (including a malformed response) is reported as broken.
 */
export function describeVerification(result: AuditVerifyResult): IntegrityVerdict {
  const checked = Math.max(0, numberOrNull(result.checked) ?? 0);
  const brokenSeq = numberOrNull(result.first_broken_seq);
  const base = {
    ok: result.ok === true,
    checked,
    brokenSeq,
    reason: textOrNull(result.reason),
    headSeq: numberOrNull(result.head_seq),
    headHash: textOrNull(result.head_hash),
    verifiedAt: textOrNull(result.verified_at),
  };
  if (result.ok === true) {
    if (checked === 0) {
      return {
        ...base,
        kind: "empty",
        headline: "No audit events to verify yet",
        summary: "The audit trail is empty, so there is no chain to check.",
      };
    }
    return {
      ...base,
      kind: "intact",
      headline: "Chain intact",
      summary: `All ${events(checked)} verified: every stored hash matches the hash recomputed from the event and the one before it, and the sequence has no gaps.`,
    };
  }
  if (brokenSeq !== null) {
    return {
      ...base,
      kind: "broken",
      headline: `Broken at seq ${brokenSeq}`,
      summary: `${events(checked)} before it verified. Treat event ${brokenSeq} and every later event as untrusted until the cause is investigated.`,
    };
  }
  return {
    ...base,
    kind: "unlocated",
    headline: "Chain broken",
    summary: `${events(checked)} verified in sequence, but the server found a problem that is not tied to a single event.`,
  };
}
