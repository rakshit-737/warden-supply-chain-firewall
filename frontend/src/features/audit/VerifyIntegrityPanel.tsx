import { useEffect, useRef, useState } from "react";
import { verifyAuditChain } from "../../api/audit";
import { isAbortError, toApiError, type ApiError } from "../../api/client";
import type { AuditVerifyResult } from "../../api/types";
import { Card } from "../../components/Card";
import { ErrorState } from "../../components/ErrorState";
import { KeyValueList, type KeyValueItem } from "../../components/KeyValueList";
import { revealInvisible } from "../../lib/text";
import { RelativeTime } from "../events/RelativeTime";
import { parseTimestamp } from "../events/time";
import { CopyButton } from "./CopyButton";
import { describeVerification, formatInteger, type IntegrityKind, type IntegrityVerdict } from "./verifyResult";

type VerifyState =
  | { status: "idle" }
  | { status: "running" }
  | { status: "done"; result: AuditVerifyResult }
  | { status: "failed"; error: ApiError };

function VerdictGlyph({ kind }: { kind: IntegrityKind }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 16 16" className="mt-0.5 h-5 w-5 shrink-0">
      {kind === "intact" && (
        <>
          <circle cx="8" cy="8" r="7" className="fill-verdict-allow" />
          <path d="M4.5 8.3 7 10.6 11.5 5.6" fill="none" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="stroke-page" />
        </>
      )}
      {(kind === "broken" || kind === "unlocated") && (
        <>
          <path d="M5.2 1h5.6L15 5.2v5.6L10.8 15H5.2L1 10.8V5.2Z" className="fill-verdict-block" />
          <path d="M8 4.2v4.6M8 11.2v.6" fill="none" strokeWidth="1.9" strokeLinecap="round" className="stroke-page" />
        </>
      )}
      {kind === "empty" && <rect x="2" y="7" width="12" height="2" rx="1" className="fill-ink-muted" />}
    </svg>
  );
}

function Verdict({ verdict }: { verdict: IntegrityVerdict }) {
  const border =
    verdict.kind === "intact" ? "border-verdict-allow" : verdict.kind === "empty" ? "border-line-strong" : "border-verdict-block";
  return (
    <div data-integrity={verdict.kind} className={`flex items-start gap-3 rounded-r-md border-l-2 bg-sunken px-4 py-3 ${border}`}>
      <VerdictGlyph kind={verdict.kind} />
      <div className="min-w-0">
        <p className="font-condensed text-xl font-semibold leading-tight text-ink">{verdict.headline}</p>
        <p className="mt-0.5 text-ink-secondary">{verdict.summary}</p>
        {verdict.reason && (
          <p className="mt-1 wrap-break-word text-ink">
            <span className="text-ink-secondary">Reason reported by the server: </span>
            {revealInvisible(verdict.reason)}
          </p>
        )}
      </div>
    </div>
  );
}

function resultItems(verdict: IntegrityVerdict, now: number): KeyValueItem[] {
  const items: KeyValueItem[] = [{ term: "Events verified", value: formatInteger(verdict.checked) }];
  if (!verdict.ok) {
    items.push({
      term: "First broken seq",
      value: verdict.brokenSeq === null ? "Not tied to a single event" : String(verdict.brokenSeq),
      mono: verdict.brokenSeq !== null,
    });
  }
  items.push(
    {
      term: verdict.ok ? "Head seq" : "Last verified seq",
      value: verdict.headSeq === null ? "None" : String(verdict.headSeq),
      mono: verdict.headSeq !== null,
    },
    {
      term: verdict.ok ? "Head hash" : "Last verified hash",
      value: verdict.headHash ? (
        <span className="flex flex-col items-start gap-1">
          <code className="break-all font-mono text-xs text-ink">{verdict.headHash}</code>
          <CopyButton value={verdict.headHash} label={verdict.ok ? "head hash" : "last verified hash"} />
        </span>
      ) : (
        "None"
      ),
    },
    {
      term: "Verified at",
      value: verdict.verifiedAt ? (
        <RelativeTime value={verdict.verifiedAt} now={Math.max(now, parseTimestamp(verdict.verifiedAt) ?? 0)} layout="inline" />
      ) : null,
    },
  );
  return items;
}

function IntegrityNote() {
  return (
    <div className="rounded-md border border-line bg-sunken px-4 py-3 text-ink-secondary">
      <p className="font-medium text-ink">Tamper-evident, not tamper-proof</p>
      <ul className="mt-1.5 flex list-disc flex-col gap-1 pl-5">
        <li>
          Every audit event stores a SHA-256 hash of its own content and of the previous event&apos;s hash. Changing, deleting or
          reordering a stored event breaks the chain from that event on, and verification reports where.
        </li>
        <li>
          The chain has no secret key. Someone who can write to the database can recompute every later hash after a change, and
          deleting the newest events leaves a shorter chain that still verifies.
        </li>
        <li>
          To detect that, regularly copy the head seq and head hash to a separate write-once place (for example a SIEM or
          object-lock storage). Later, check that the event with that seq still has the same event hash and that the head seq has
          not gone backwards.
        </li>
        <li>A result describes the chain at its verification time. Events recorded afterwards are not covered.</li>
      </ul>
    </div>
  );
}

/** On-demand verification of the audit hash chain (GET /audit/verify, audit:read). */
export function VerifyIntegrityPanel({ now }: { now: number }) {
  const [state, setState] = useState<VerifyState>({ status: "idle" });
  const controllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const controllers = controllerRef;
    return () => controllers.current?.abort();
  }, []);

  async function verify() {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState({ status: "running" });
    try {
      const result = await verifyAuditChain({ signal: controller.signal });
      if (!controller.signal.aborted) setState({ status: "done", result });
    } catch (err) {
      if (controller.signal.aborted || isAbortError(err)) return;
      setState({ status: "failed", error: toApiError(err) });
    }
  }

  const running = state.status === "running";
  const verdict = state.status === "done" ? describeVerification(state.result) : null;

  return (
    <Card
      title="Hash chain integrity"
      description="Recomputes every hash of the audit trail on the server."
      actions={
        <button
          type="button"
          className="btn-primary"
          aria-disabled={running || undefined}
          onClick={() => {
            if (!running) void verify();
          }}
        >
          {running ? "Verifying" : verdict ? "Verify again" : "Verify integrity"}
        </button>
      }
    >
      <div className="flex flex-col gap-4">
        <div role="status" aria-live="polite" aria-busy={running || undefined}>
          {state.status === "idle" && (
            <p className="text-ink-secondary">
              Not verified yet. Verification reads every audit event, so it can take a while on a long trail.
            </p>
          )}
          {running && (
            <p className="flex items-center gap-3 text-ink">
              <span
                aria-hidden="true"
                className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-line-strong border-t-accent"
              />
              Verifying the hash chain.
            </p>
          )}
          {verdict && <Verdict verdict={verdict} />}
          {state.status === "failed" && <p className="text-ink-secondary">Verification did not complete, so no result is shown.</p>}
        </div>
        {state.status === "failed" && (
          <ErrorState
            title="The chain could not be verified"
            error={state.error}
            onRetry={() => void verify()}
            retryLabel="Verify again"
          />
        )}
        {verdict && <KeyValueList columns={2} items={resultItems(verdict, now)} />}
        <IntegrityNote />
      </div>
    </Card>
  );
}
