import { useEffect, useId, useRef, useState } from "react";
import { toApiError, type ApiError } from "../../api/client";
import { transitionException, type ExceptionAction } from "../../api/exceptions";
import type { PolicyException } from "../../api/types";
import { CodeBlock } from "../../components/CodeBlock";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { ErrorState } from "../../components/ErrorState";
import { KeyValueList } from "../../components/KeyValueList";
import { formatDateTime, humanize } from "../../lib/format";
import { ScopeChips } from "./ScopeChips";
import { MAX_COMMENT_CHARS, charCount, commentError } from "./validation";

export interface TransitionRequest {
  exception: PolicyException;
  action: ExceptionAction;
}

export interface TransitionDialogProps {
  /** null keeps the dialog closed. */
  request: TransitionRequest | null;
  currentUserId: string | null;
  onDone: (updated: PolicyException, action: ExceptionAction) => void;
  onCancel: () => void;
  /** The server reported the exception changed or disappeared (409 or 404): reload what is shown. */
  onStale: () => void;
}

interface Copy {
  title: string;
  description: string;
  confirmLabel: string;
  tone: "default" | "danger";
  failure: string;
}

function copyFor(action: ExceptionAction, exception: PolicyException, withdrawing: boolean): Copy {
  const pkg = exception.package;
  switch (action) {
    case "approve":
      return {
        title: `Approve the exception for ${pkg}?`,
        description: `Findings in its scope stop counting against policy until it expires (${formatDateTime(exception.expires_at)}) or is revoked. Your approval and comment are recorded in the audit trail.`,
        confirmLabel: "Approve exception",
        tone: "default",
        failure: "The exception was not approved",
      };
    case "reject":
      return {
        title: `Reject the exception request for ${pkg}?`,
        description: "Rejection is final: the request cannot be approved later, and a new request would be needed.",
        confirmLabel: "Reject request",
        tone: "danger",
        failure: "The request was not rejected",
      };
    case "revoke":
      return withdrawing
        ? {
            title: `Withdraw your exception request for ${pkg}?`,
            description: "The request is closed and can no longer be approved. A new request would be needed.",
            confirmLabel: "Withdraw request",
            tone: "danger",
            failure: "The request was not withdrawn",
          }
        : {
            title: `Revoke the exception for ${pkg}?`,
            description: "It stops applying immediately and cannot be reinstated. A new request would be needed.",
            confirmLabel: "Revoke exception",
            tone: "danger",
            failure: "The exception was not revoked",
          };
  }
}

function describeFailure(error: ApiError, copy: Copy): { title: string; error: ApiError } {
  if (error.status === 403 && error.code === "separation_of_duties") {
    return { title: "Separation of duties: a different approver must decide this request", error };
  }
  if (error.status === 403) return { title: "Your role does not allow this", error };
  if (error.status === 409 || error.status === 404) {
    return {
      title: error.status === 404 ? "This exception no longer exists" : "The exception changed before this was saved",
      error: { ...error, message: `${error.message} The list has been refreshed to show its current state.` },
    };
  }
  return { title: copy.failure, error };
}

/**
 * Confirmation for approve, reject and revoke. A comment is required (the server accepts none, but every
 * decision should say why); it is validated before sending, and server refusals such as separation of
 * duties (403) or a concurrent change (409) are shown inside the dialog.
 */
export function TransitionDialog({ request, ...rest }: TransitionDialogProps) {
  if (!request) return null;
  return <TransitionDialogBody key={`${request.exception.id}:${request.action}`} request={request} {...rest} />;
}

function TransitionDialogBody({
  request: { exception, action },
  currentUserId,
  onDone,
  onCancel,
  onStale,
}: TransitionDialogProps & { request: TransitionRequest }) {
  const commentId = useId();
  const [comment, setComment] = useState("");
  const [showValidation, setShowValidation] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const commentRef = useRef<HTMLTextAreaElement>(null);
  const [commentFocusRequest, setCommentFocusRequest] = useState(0);

  useEffect(() => {
    if (commentFocusRequest > 0) commentRef.current?.focus();
  }, [commentFocusRequest]);

  const withdrawing =
    action === "revoke" && currentUserId !== null && exception.requested_by === currentUserId && exception.status === "pending";
  const copy = copyFor(action, exception, withdrawing);
  const validation = commentError(comment);
  const shownValidation = showValidation ? validation : null;
  const shownFailure = failure ? describeFailure(failure, copy) : null;

  async function confirm() {
    if (busy) return;
    if (validation) {
      setShowValidation(true);
      setCommentFocusRequest((n) => n + 1);
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      const updated = await transitionException(exception.id, action, comment);
      onDone(updated, action);
    } catch (err) {
      const apiError = toApiError(err);
      if (apiError.status === 409 || apiError.status === 404) onStale();
      setFailure(apiError);
      setBusy(false);
    }
  }

  return (
    <ConfirmDialog
      open
      title={copy.title}
      description={copy.description}
      confirmLabel={copy.confirmLabel}
      tone={copy.tone}
      busy={busy}
      onConfirm={() => void confirm()}
      onCancel={() => {
        if (!busy) onCancel();
      }}
    >
      <div className="flex flex-col gap-3">
        <KeyValueList
          items={[
            { term: "Versions", value: exception.version_spec ?? "Every version", mono: exception.version_spec !== null },
            { term: "Environment", value: exception.environment ? humanize(exception.environment) : "Every environment" },
            {
              term: "Scope",
              value: <ScopeChips codes={exception.codes} categories={exception.categories} limit={6} />,
            },
          ]}
        />
        <CodeBlock label="Justification" value={exception.justification} maxChars={2000} className="[&_pre]:max-h-40" />
        <div>
          <label htmlFor={commentId} className="label">
            Comment
          </label>
          <textarea
            ref={commentRef}
            id={commentId}
            rows={3}
            required
            className="input font-sans text-[0.8125rem]"
            value={comment}
            aria-invalid={shownValidation ? true : undefined}
            aria-describedby={`${commentId}-hint ${commentId}-error`}
            onChange={(event) => setComment(event.target.value)}
          />
          <p id={`${commentId}-hint`} className="mt-1 text-xs text-ink-muted">
            Required. Recorded in the audit trail.{" "}
            <span className="tabular-nums">
              {charCount(comment)} / {MAX_COMMENT_CHARS}
            </span>
          </p>
          <p id={`${commentId}-error`} aria-live="polite" className="text-xs text-sev-critical">
            {shownValidation}
          </p>
        </div>
        {shownFailure && <ErrorState title={shownFailure.title} error={shownFailure.error} />}
      </div>
    </ConfirmDialog>
  );
}
