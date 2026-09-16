import { useId, useState } from "react";
import { toApiError, type ApiError } from "../../api/client";
import { USER_ROLES, type User, type UserRole } from "../../api/types";
import { updateUser } from "../../api/users";
import { ROLE_LABELS } from "../../auth/permissions";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { ErrorState } from "../../components/ErrorState";
import { pickOption } from "../../lib/values";
import { asSentence, isLastAdminError } from "./registration";
import { ROLE_OPTIONS, ROLE_SUMMARIES, describeRole } from "./roles";

export type UserChange = { kind: "role"; user: User } | { kind: "status"; user: User; activate: boolean };

export interface UserChangeResult {
  user: User;
  /** Confirmation to show once the dialog has closed. */
  message: string;
}

export interface UserChangeDialogProps {
  change: UserChange;
  /** True when the account being changed belongs to the signed-in user. */
  isSelf: boolean;
  onCancel: () => void;
  onChanged: (result: UserChangeResult) => void;
}

function successMessage(change: UserChange, updated: User): string {
  if (change.kind === "role") return `${updated.email} now has the ${describeRole(updated.role).label} role.`;
  return updated.is_active
    ? `Reactivated ${updated.email}. They can sign in again.`
    : `Deactivated ${updated.email}. Their sessions have been ended.`;
}

/**
 * Confirmation for a role change or for deactivating or reactivating an account. The dialog stays
 * open with the server's reason when the change is refused, including the last-admin protection.
 * Mount it with a key per user and change so its state starts fresh.
 */
export function UserChangeDialog({ change, isSelf, onCancel, onChanged }: UserChangeDialogProps) {
  const current = describeRole(change.user.role);
  const [role, setRole] = useState<UserRole>(current.role ?? "read_only");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const selectId = useId();
  const summaryId = useId();
  const email = change.user.email;

  async function confirm() {
    if (busy) return;
    setError(null);
    setProblem(null);
    if (change.kind === "role" && role === current.role) {
      setProblem("This user already has that role. Choose a different role, or cancel.");
      return;
    }
    setBusy(true);
    try {
      const updated = await updateUser(
        change.user.id,
        change.kind === "role" ? { role } : { is_active: change.activate },
      );
      onChanged({ user: updated, message: successMessage(change, updated) });
    } catch (err) {
      setError(toApiError(err));
      setBusy(false);
    }
  }

  const errorBlock = error ? (
    isLastAdminError(error) ? (
      <ErrorState
        title="At least one active admin must remain"
        error={{
          ...error,
          message: `${asSentence(error.message)} Make another user an active admin first, then try again.`,
        }}
      />
    ) : (
      <ErrorState title="The change was not saved" error={error} />
    )
  ) : null;

  const cancel = () => {
    if (!busy) onCancel();
  };

  if (change.kind === "role") {
    return (
      <ConfirmDialog
        open
        title={`Change role for ${email}`}
        description="The new permissions apply from their next request."
        confirmLabel="Change role"
        busy={busy}
        onConfirm={() => void confirm()}
        onCancel={cancel}
      >
        <div className="flex flex-col gap-3">
          <p className="text-ink-secondary">
            Current role: <span className="text-ink">{current.label}</span>
            {current.reportedAs && (
              <span className="text-ink-muted">
                {" "}
                (reported as <code className="font-mono">{current.reportedAs}</code>)
              </span>
            )}
          </p>
          <div>
            <label htmlFor={selectId} className="label">
              New role
            </label>
            <select
              id={selectId}
              className="input pr-8"
              value={role}
              disabled={busy}
              aria-describedby={summaryId}
              onChange={(event) => {
                setProblem(null);
                setRole(pickOption(USER_ROLES, event.target.value) ?? "read_only");
              }}
            >
              {ROLE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <p id={summaryId} className="mt-1 text-xs text-ink-secondary">
              {ROLE_LABELS[role]}: {ROLE_SUMMARIES[role]}
            </p>
          </div>
          {isSelf && role !== "admin" && (
            <p className="rounded-r border-l-2 border-sev-medium bg-sunken px-3 py-2 text-ink">
              This is your own account. Without the admin role you can no longer manage users once the change is saved.
            </p>
          )}
          {problem && (
            <p role="alert" className="rounded-r border-l-2 border-sev-critical bg-sunken px-3 py-2 text-ink">
              {problem}
            </p>
          )}
          {errorBlock}
        </div>
      </ConfirmDialog>
    );
  }

  const roleLabel = current.label.toLowerCase();
  return (
    <ConfirmDialog
      open
      title={change.activate ? `Reactivate ${email}?` : `Deactivate ${email}?`}
      description={
        change.activate
          ? `They can sign in again with their existing password, with the ${roleLabel} role.`
          : "They are signed out everywhere: their refresh tokens are revoked and their access ends with their next request. The account and its history are kept, and it can be reactivated later."
      }
      confirmLabel={change.activate ? "Reactivate user" : "Deactivate user"}
      tone={change.activate ? "default" : "danger"}
      busy={busy}
      onConfirm={() => void confirm()}
      onCancel={cancel}
    >
      {(isSelf && !change.activate) || errorBlock ? (
        <div className="flex flex-col gap-3">
          {isSelf && !change.activate && (
            <p className="rounded-r border-l-2 border-sev-medium bg-sunken px-3 py-2 text-ink">
              This is your own account. You will be signed out.
            </p>
          )}
          {errorBlock}
        </div>
      ) : null}
    </ConfirmDialog>
  );
}
