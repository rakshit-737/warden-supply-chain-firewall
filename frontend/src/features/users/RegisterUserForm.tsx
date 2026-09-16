import { useEffect, useRef, useState, type FormEvent } from "react";
import { toApiError, type ApiError } from "../../api/client";
import { USER_ROLES, type User } from "../../api/types";
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, registerUser } from "../../api/users";
import { ROLE_LABELS } from "../../auth/permissions";
import { ErrorState } from "../../components/ErrorState";
import { pickOption } from "../../lib/values";
import {
  EMPTY_REGISTRATION,
  REGISTRATION_FIELDS,
  asSentence,
  validateRegistration,
  type RegistrationErrors,
  type RegistrationField,
  type RegistrationValues,
} from "./registration";
import { ROLE_OPTIONS, ROLE_SUMMARIES } from "./roles";

export interface RegisterUserFormProps {
  onRegistered: (user: User) => void;
  onCancel: () => void;
}

const FIELD_IDS: Readonly<Record<RegistrationField | "role", string>> = {
  email: "register-user-email",
  password: "register-user-password",
  confirmPassword: "register-user-confirm",
  role: "register-user-role",
};

function FieldError({ field, message }: { field: RegistrationField; message: string | undefined }) {
  if (!message) return null;
  return (
    <p id={`${FIELD_IDS[field]}-error`} className="mt-1 flex items-start gap-1.5 text-xs text-ink">
      <span aria-hidden="true" className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-sev-critical" />
      {message}
    </p>
  );
}

function describedBy(...ids: (string | false | undefined)[]): string | undefined {
  const present = ids.filter((id): id is string => typeof id === "string" && id !== "");
  return present.length > 0 ? present.join(" ") : undefined;
}

function inputClass(invalid: boolean): string {
  return invalid ? "input border-sev-critical" : "input";
}

/**
 * Registers an account (POST /auth/register). Validation mirrors the server: errors are shown next to
 * their fields, linked with aria-describedby, counted in an alert, and focus moves to the first field
 * that needs attention. The password is never shown back or kept after the form closes.
 */
export function RegisterUserForm({ onRegistered, onCancel }: RegisterUserFormProps) {
  const [values, setValues] = useState<RegistrationValues>(EMPTY_REGISTRATION);
  const [errors, setErrors] = useState<RegistrationErrors>({});
  const [serverError, setServerError] = useState<ApiError | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [focusRequest, setFocusRequest] = useState<{ field: RegistrationField; attempt: number } | null>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    emailRef.current?.focus();
  }, []);

  // Runs after the error text has rendered, so the field is announced together with its error.
  useEffect(() => {
    if (!focusRequest) return;
    const target =
      focusRequest.field === "email" ? emailRef : focusRequest.field === "password" ? passwordRef : confirmRef;
    target.current?.focus();
  }, [focusRequest]);

  function requestFocus(field: RegistrationField) {
    setFocusRequest((previous) => ({ field, attempt: (previous?.attempt ?? 0) + 1 }));
  }

  function update(field: RegistrationField, value: string) {
    setValues((previous) => ({ ...previous, [field]: value }));
    setErrors((previous) => {
      if (!previous[field]) return previous;
      const next = { ...previous };
      delete next[field];
      return next;
    });
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    const result = validateRegistration(values);
    setErrors(result.errors);
    setServerError(null);
    if (!result.body) {
      const first = REGISTRATION_FIELDS.find((field) => result.errors[field]);
      if (first) requestFocus(first);
      return;
    }
    setSubmitting(true);
    try {
      const created = await registerUser(result.body);
      onRegistered(created);
    } catch (err) {
      const apiError = toApiError(err);
      if (apiError.status === 409) {
        setErrors({ email: asSentence(apiError.message) || "A user with that email already exists." });
        requestFocus("email");
      } else {
        setServerError(apiError);
      }
      setSubmitting(false);
    }
  }

  const errorCount = Object.keys(errors).length;
  const passwordHintId = `${FIELD_IDS.password}-hint`;
  const roleHintId = `${FIELD_IDS.role}-hint`;

  return (
    <form onSubmit={(event) => void submit(event)} noValidate className="flex flex-col gap-4">
      {errorCount > 0 && (
        <p role="alert" className="rounded-r border-l-2 border-sev-critical bg-sunken px-3 py-2 text-ink">
          {errorCount === 1 ? "Fix 1 problem to register this user." : `Fix ${errorCount} problems to register this user.`}
        </p>
      )}
      <fieldset disabled={submitting} className="flex min-w-0 flex-col gap-4">
        <legend className="sr-only">New user</legend>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor={FIELD_IDS.email} className="label">
              Email
            </label>
            <input
              ref={emailRef}
              id={FIELD_IDS.email}
              type="email"
              inputMode="email"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              maxLength={320}
              required
              className={inputClass(Boolean(errors.email))}
              aria-invalid={errors.email ? true : undefined}
              aria-describedby={describedBy(errors.email && `${FIELD_IDS.email}-error`)}
              value={values.email}
              onChange={(event) => update("email", event.target.value)}
            />
            <FieldError field="email" message={errors.email} />
          </div>
          <div>
            <label htmlFor={FIELD_IDS.role} className="label">
              Role
            </label>
            <select
              id={FIELD_IDS.role}
              className="input pr-8"
              value={values.role}
              aria-describedby={roleHintId}
              onChange={(event) =>
                setValues((previous) => ({ ...previous, role: pickOption(USER_ROLES, event.target.value) ?? "read_only" }))
              }
            >
              {ROLE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <p id={roleHintId} className="mt-1 text-xs text-ink-muted">
              {ROLE_LABELS[values.role]}: {ROLE_SUMMARIES[values.role]}
            </p>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor={FIELD_IDS.password} className="label">
              Password
            </label>
            <input
              ref={passwordRef}
              id={FIELD_IDS.password}
              type="password"
              autoComplete="new-password"
              maxLength={PASSWORD_MAX_LENGTH * 2}
              required
              className={inputClass(Boolean(errors.password))}
              aria-invalid={errors.password ? true : undefined}
              aria-describedby={describedBy(errors.password && `${FIELD_IDS.password}-error`, passwordHintId)}
              value={values.password}
              onChange={(event) => update("password", event.target.value)}
            />
            <FieldError field="password" message={errors.password} />
            <p id={passwordHintId} className="mt-1 text-xs text-ink-muted">
              At least {PASSWORD_MIN_LENGTH} characters. Share it with the person through a secure channel.
            </p>
          </div>
          <div>
            <label htmlFor={FIELD_IDS.confirmPassword} className="label">
              Confirm password
            </label>
            <input
              ref={confirmRef}
              id={FIELD_IDS.confirmPassword}
              type="password"
              autoComplete="new-password"
              maxLength={PASSWORD_MAX_LENGTH * 2}
              required
              className={inputClass(Boolean(errors.confirmPassword))}
              aria-invalid={errors.confirmPassword ? true : undefined}
              aria-describedby={describedBy(errors.confirmPassword && `${FIELD_IDS.confirmPassword}-error`)}
              value={values.confirmPassword}
              onChange={(event) => update("confirmPassword", event.target.value)}
            />
            <FieldError field="confirmPassword" message={errors.confirmPassword} />
          </div>
        </div>
      </fieldset>

      {serverError && <ErrorState error={serverError} title="The user was not registered" />}

      <div className="flex flex-wrap items-center gap-2">
        <button type="submit" className="btn-primary" aria-disabled={submitting || undefined}>
          {submitting ? "Registering" : "Register user"}
        </button>
        <button type="button" className="btn-ghost" disabled={submitting} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
