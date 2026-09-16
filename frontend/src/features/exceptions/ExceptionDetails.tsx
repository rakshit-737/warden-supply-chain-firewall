import { useId, type ReactNode } from "react";
import type { ExceptionAction } from "../../api/exceptions";
import type { PolicyException } from "../../api/types";
import { Card } from "../../components/Card";
import { CodeBlock } from "../../components/CodeBlock";
import { KeyValueList, type KeyValueItem } from "../../components/KeyValueList";
import { formatDateTime, humanize } from "../../lib/format";
import { ExceptionStatusBadge } from "./ExceptionStatusBadge";
import { ExpiryCountdown } from "./ExpiryCountdown";
import { ScopeChips } from "./ScopeChips";
import { effectiveStatus, isOpenStatus } from "./expiry";

export interface ExceptionDetailsProps {
  exception: PolicyException;
  now: number;
  currentUserId: string | null;
  canApprove: boolean;
  canRequest: boolean;
  /** Display name of a policy id, or null when it is not known. */
  policyLabel: (policyId: string) => string | null;
  onAction: (action: ExceptionAction) => void;
}

function Person({ id, currentUserId }: { id: string; currentUserId: string | null }) {
  if (id === currentUserId) return <>You</>;
  return <code className="break-all font-mono text-xs">{id}</code>;
}

/**
 * One exception with its justification and the actions the signed-in user may take. The action rules
 * mirror the server (which enforces them): approvers decide pending requests except their own
 * (separation of duties); approvers revoke any open exception and requesters may withdraw their own.
 */
export function ExceptionDetails({
  exception,
  now,
  currentUserId,
  canApprove,
  canRequest,
  policyLabel,
  onAction,
}: ExceptionDetailsProps) {
  const separationNoteId = useId();
  const status = effectiveStatus(exception, now);
  const own = currentUserId !== null && exception.requested_by === currentUserId;
  const pending = status === "pending";
  const showDecide = canApprove && pending;
  const showRevoke = isOpenStatus(status) && (canApprove || (canRequest && own));

  const items: KeyValueItem[] = [
    {
      key: "versions",
      term: "Versions",
      value: exception.version_spec ?? "Every version",
      mono: exception.version_spec !== null,
    },
    {
      key: "environment",
      term: "Environment",
      value: exception.environment ? humanize(exception.environment) : "Every environment",
    },
    {
      key: "policy",
      term: "Policy",
      value: exception.policy_id
        ? (policyLabel(exception.policy_id) ?? <code className="break-all font-mono text-xs">{exception.policy_id}</code>)
        : "Every policy",
    },
    {
      key: "categories",
      term: "Finding categories",
      value: <ScopeChips codes={[]} categories={exception.categories} emptyText="None selected" />,
    },
    {
      key: "codes",
      term: "Finding codes",
      value: <ScopeChips codes={exception.codes} categories={[]} emptyText="None selected" />,
    },
    { key: "requested-by", term: "Requested by", value: <Person id={exception.requested_by} currentUserId={currentUserId} /> },
    { key: "requested-at", term: "Requested", value: formatDateTime(exception.created_at) },
  ];
  if (exception.approved_by) {
    items.push({
      key: "decided-by",
      term: exception.status === "rejected" ? "Rejected by" : "Approved by",
      value: <Person id={exception.approved_by} currentUserId={currentUserId} />,
    });
  }
  if (exception.decided_at) {
    items.push({
      key: "decided-at",
      term: exception.status === "rejected" ? "Rejected" : "Approved",
      value: formatDateTime(exception.decided_at),
    });
  }
  if (exception.revoked_by) {
    items.push({ key: "revoked-by", term: "Revoked by", value: <Person id={exception.revoked_by} currentUserId={currentUserId} /> });
  }
  if (exception.revoked_at) items.push({ key: "revoked-at", term: "Revoked", value: formatDateTime(exception.revoked_at) });
  items.push({ key: "id", term: "Exception id", value: exception.id, mono: true });

  let explanation: ReactNode = null;
  if (status === "expired") {
    explanation = "This exception has expired. It no longer applies and can no longer be approved or revoked. Request a new one if it is still needed.";
  } else if (status === "rejected") {
    explanation = "This request was rejected. Rejection is final.";
  } else if (status === "revoked") {
    explanation = "This exception was revoked or withdrawn and no longer applies.";
  } else if (pending && !canApprove) {
    explanation = "Waiting for a decision by someone with the exception:approve permission (the admin or security analyst roles).";
  } else if (status === "approved" && !showRevoke) {
    explanation = "Only an approver or the person who requested it can revoke this exception.";
  }

  return (
    <Card
      title={<span className="break-all font-mono">{exception.package}</span>}
      description="Exception details"
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <ExceptionStatusBadge status={status} />
          <ExpiryCountdown exception={exception} now={now} />
        </div>
        <KeyValueList items={items} />
        <CodeBlock label="Justification" value={exception.justification} />

        <div className="flex flex-col gap-2 border-t border-line pt-3">
          <h3 className="text-xs font-medium text-ink-secondary">Actions</h3>
          {explanation && <p className="text-ink-secondary">{explanation}</p>}
          {showDecide && own && (
            <p id={separationNoteId} className="rounded-r border-l-2 border-accent bg-sunken px-3 py-2 text-ink">
              You requested this exception, so you cannot approve or reject it. Separation of duties requires a different
              approver to decide it.{showRevoke ? " You can still withdraw it." : ""}
            </p>
          )}
          {(showDecide || showRevoke) && (
            <div className="flex flex-wrap gap-2">
              {showDecide && (
                <>
                  <button
                    type="button"
                    className="btn-primary"
                    aria-disabled={own || undefined}
                    aria-describedby={own ? separationNoteId : undefined}
                    onClick={() => {
                      if (!own) onAction("approve");
                    }}
                  >
                    Approve
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    aria-disabled={own || undefined}
                    aria-describedby={own ? separationNoteId : undefined}
                    onClick={() => {
                      if (!own) onAction("reject");
                    }}
                  >
                    Reject
                  </button>
                </>
              )}
              {showRevoke && (
                <button type="button" className="btn-secondary" onClick={() => onAction("revoke")}>
                  {own && pending ? "Withdraw request" : "Revoke"}
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
