import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { toApiError, type ApiError } from "../../api/client";
import { requestException } from "../../api/exceptions";
import { ENVIRONMENTS, type Policy, type PolicyException } from "../../api/types";
import { Card } from "../../components/Card";
import { ErrorState } from "../../components/ErrorState";
import { formatDateTime, humanize } from "../../lib/format";
import { pickOption } from "../../lib/values";
import { EXCEPTION_FIELD_IDS } from "./formIds";
import { ScopePicker } from "./ScopePicker";
import { formatTimeSpan } from "./expiry";
import { currentTime, useNow } from "./useNow";
import {
  EMPTY_EXCEPTION_FORM,
  EXCEPTION_FORM_FIELDS,
  MAX_EXCEPTION_DAYS,
  MAX_JUSTIFICATION_CHARS,
  MAX_PACKAGE_NAME_CHARS,
  MAX_VERSION_SPEC_CHARS,
  MIN_JUSTIFICATION_CHARS,
  charCount,
  checkExpiry,
  expiryBounds,
  normalizePackageName,
  validateExceptionForm,
  type ExceptionFormField,
  type ExceptionFormValues,
} from "./validation";

const FIELD_LABELS: Readonly<Record<ExceptionFormField, string>> = {
  package: "Package name",
  versionSpec: "Version specifier",
  policyId: "Policy",
  environment: "Environment",
  categories: "Finding categories",
  codes: "Finding codes",
  justification: "Justification",
  expiresOn: "Expiry date",
};

const IDS = EXCEPTION_FIELD_IDS;

export interface ExceptionRequestFormProps {
  /** Policies a request can be tied to; undefined while loading. */
  policies: readonly Policy[] | undefined;
  policiesError: ApiError | null;
  onRetryPolicies: () => void;
  onCreated: (exception: PolicyException) => void;
  onCancel: () => void;
}

function Hint({ id, children }: { id: string; children: ReactNode }) {
  return (
    <p id={id} className="mt-1 text-xs text-ink-muted">
      {children}
    </p>
  );
}

/** Always rendered (empty when valid) so a message that appears is announced politely. */
function FieldError({ id, message }: { id: string; message: string | undefined }) {
  return (
    <p id={id} aria-live="polite" className="text-xs text-sev-critical empty:hidden">
      {message}
    </p>
  );
}

/**
 * Form for POST /policies/exceptions (exception:request). Each field is checked against the server's
 * rules once it has been visited or a submit was attempted; a failed submit lists every problem in a
 * focused summary whose entries move focus to the field.
 */
export function ExceptionRequestForm({ policies, policiesError, onRetryPolicies, onCreated, onCancel }: ExceptionRequestFormProps) {
  const now = useNow();
  const summaryTitleId = useId();
  const [values, setValues] = useState<ExceptionFormValues>(EMPTY_EXCEPTION_FORM);
  const [touched, setTouched] = useState<ReadonlySet<ExceptionFormField>>(() => new Set());
  const [attempted, setAttempted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [serverError, setServerError] = useState<ApiError | null>(null);
  const packageRef = useRef<HTMLInputElement>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const [summaryFocusRequest, setSummaryFocusRequest] = useState(0);

  useEffect(() => {
    packageRef.current?.focus();
  }, []);

  useEffect(() => {
    if (summaryFocusRequest > 0) summaryRef.current?.focus();
  }, [summaryFocusRequest]);

  const selectedPolicy = values.policyId ? (policies?.find((policy) => policy.id === values.policyId) ?? null) : null;
  const policyEnvironment = selectedPolicy ? (pickOption(ENVIRONMENTS, selectedPolicy.environment) ?? null) : null;
  const { errors } = validateExceptionForm(values, now, policyEnvironment);
  const shown = (field: ExceptionFormField) => (attempted || touched.has(field) ? errors[field] : undefined);
  const summary = attempted ? EXCEPTION_FORM_FIELDS.filter((field) => errors[field]) : [];

  const bounds = expiryBounds(now);
  const expiry = checkExpiry(values.expiresOn, now);
  const normalisedName = values.package.trim() && !errors.package ? normalizePackageName(values.package) : null;

  function set<K extends ExceptionFormField>(field: K, value: ExceptionFormValues[K]) {
    setValues((previous) => ({ ...previous, [field]: value }));
  }

  function touch(field: ExceptionFormField) {
    setTouched((previous) => (previous.has(field) ? previous : new Set(previous).add(field)));
  }

  function describedBy(field: ExceptionFormField): string {
    return `${IDS[field]}-hint ${IDS[field]}-error`;
  }

  function choosePolicy(policyId: string) {
    const policy = policies?.find((candidate) => candidate.id === policyId) ?? null;
    const environment = policy ? pickOption(ENVIRONMENTS, policy.environment) : undefined;
    setValues((previous) => ({
      ...previous,
      policyId: policy ? policy.id : "",
      environment: environment ?? previous.environment,
    }));
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    // Validate against the clock at submit time: the rendered `now` can be up to one refresh interval old.
    const result = validateExceptionForm(values, currentTime(), policyEnvironment);
    setAttempted(true);
    setServerError(null);
    if (!result.body) {
      setSummaryFocusRequest((n) => n + 1);
      return;
    }
    setSubmitting(true);
    try {
      onCreated(await requestException(result.body));
    } catch (err) {
      setServerError(toApiError(err));
      setSubmitting(false);
    }
  }

  return (
    <Card
      title="Request a policy exception"
      description="An exception lets specific findings for one package pass policy until it expires. Someone other than you must approve it."
    >
      <form onSubmit={(event) => void submit(event)} noValidate className="flex flex-col gap-4">
        {summary.length > 0 && (
          <div
            ref={summaryRef}
            tabIndex={-1}
            role="alert"
            aria-labelledby={summaryTitleId}
            className="rounded-r border-l-2 border-sev-critical bg-sunken px-3 py-2"
          >
            <p id={summaryTitleId} className="font-medium text-ink">
              {summary.length === 1 ? "Fix 1 problem before sending the request" : `Fix ${summary.length} problems before sending the request`}
            </p>
            <ul className="mt-1 flex flex-col gap-0.5">
              {summary.map((field) => (
                <li key={field}>
                  <button
                    type="button"
                    className="text-left text-ink-secondary underline hover:text-ink"
                    onClick={() => document.getElementById(IDS[field])?.focus()}
                  >
                    {FIELD_LABELS[field]}: {errors[field]}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <fieldset disabled={submitting} className="flex min-w-0 flex-col gap-4">
          <legend className="sr-only">Exception request</legend>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label htmlFor={IDS.package} className="label">
                Package name
              </label>
              <input
                ref={packageRef}
                id={IDS.package}
                className="input font-mono"
                required
                maxLength={MAX_PACKAGE_NAME_CHARS}
                autoComplete="off"
                spellCheck={false}
                placeholder="internal-package"
                value={values.package}
                aria-invalid={shown("package") ? true : undefined}
                aria-describedby={describedBy("package")}
                onChange={(event) => set("package", event.target.value)}
                onBlur={() => touch("package")}
              />
              <Hint id={`${IDS.package}-hint`}>
                {normalisedName ? (
                  <>
                    Stored as <code className="break-all font-mono text-ink">{normalisedName}</code> (PEP 503 normalised
                    name).
                  </>
                ) : (
                  "The PyPI project name. It is stored normalised, so Foo_Bar and foo-bar are the same package."
                )}
              </Hint>
              <FieldError id={`${IDS.package}-error`} message={shown("package")} />
            </div>
            <div>
              <label htmlFor={IDS.versionSpec} className="label">
                Version specifier
              </label>
              <input
                id={IDS.versionSpec}
                className="input font-mono"
                maxLength={MAX_VERSION_SPEC_CHARS}
                autoComplete="off"
                spellCheck={false}
                placeholder="Every version"
                value={values.versionSpec}
                aria-invalid={shown("versionSpec") ? true : undefined}
                aria-describedby={describedBy("versionSpec")}
                onChange={(event) => set("versionSpec", event.target.value)}
                onBlur={() => touch("versionSpec")}
              />
              <Hint id={`${IDS.versionSpec}-hint`}>Optional PEP 440 specifier set, such as {">=1.4,<2.0"}.</Hint>
              <FieldError id={`${IDS.versionSpec}-error`} message={shown("versionSpec")} />
            </div>
            <div>
              <label htmlFor={IDS.policyId} className="label">
                Policy
              </label>
              <select
                id={IDS.policyId}
                className="input pr-8"
                value={values.policyId}
                aria-describedby={describedBy("policyId")}
                onChange={(event) => choosePolicy(event.target.value)}
              >
                <option value="">Every policy</option>
                {(policies ?? []).map((policy) => (
                  <option key={policy.id} value={policy.id}>
                    {policy.name} ({humanize(policy.environment ?? "production")}
                    {policy.is_active ? ", active" : ""})
                  </option>
                ))}
              </select>
              <Hint id={`${IDS.policyId}-hint`}>
                {policiesError ? (
                  <>
                    Policies could not be loaded, so the request can only apply to every policy.{" "}
                    <button type="button" className="text-ink underline" onClick={onRetryPolicies}>
                      Load policies again
                    </button>
                  </>
                ) : policies === undefined ? (
                  "Loading policies."
                ) : (
                  "Optional. Limit the exception to one policy."
                )}
              </Hint>
              <FieldError id={`${IDS.policyId}-error`} message={shown("policyId")} />
            </div>
            <div>
              <label htmlFor={IDS.environment} className="label">
                Environment
              </label>
              <select
                id={IDS.environment}
                className="input pr-8"
                value={values.environment}
                disabled={policyEnvironment !== null}
                aria-invalid={shown("environment") ? true : undefined}
                aria-describedby={describedBy("environment")}
                onChange={(event) => set("environment", pickOption(ENVIRONMENTS, event.target.value) ?? "")}
              >
                <option value="">Every environment</option>
                {ENVIRONMENTS.map((environment) => (
                  <option key={environment} value={environment}>
                    {humanize(environment)}
                  </option>
                ))}
              </select>
              <Hint id={`${IDS.environment}-hint`}>
                {policyEnvironment
                  ? `Set by the selected policy (${humanize(policyEnvironment)}).`
                  : "Optional. Leave as every environment to apply it wherever the policy is evaluated."}
              </Hint>
              <FieldError id={`${IDS.environment}-error`} message={shown("environment")} />
            </div>
          </div>

          <div>
            <h3 className="text-[0.8125rem] font-semibold text-ink">Scope</h3>
            <p className="mb-2 text-xs text-ink-secondary">
              Narrow the exception to the findings you have reviewed. Without any codes or categories the request is not
              limited to specific findings, and approvers will expect a reason for that.
            </p>
            <ScopePicker
              codes={values.codes}
              categories={values.categories}
              onCodesChange={(codes) => {
                set("codes", codes);
                touch("codes");
              }}
              onCategoriesChange={(categories) => {
                set("categories", categories);
                touch("categories");
              }}
              codesError={shown("codes")}
              categoriesError={shown("categories")}
            />
          </div>

          <div>
            <label htmlFor={IDS.justification} className="label">
              Justification
            </label>
            <textarea
              id={IDS.justification}
              rows={4}
              required
              className="input font-sans text-[0.8125rem]"
              value={values.justification}
              aria-invalid={shown("justification") ? true : undefined}
              aria-describedby={describedBy("justification")}
              onChange={(event) => set("justification", event.target.value)}
              onBlur={() => touch("justification")}
            />
            <Hint id={`${IDS.justification}-hint`}>
              Why the findings are acceptable, and what limits the risk. At least {MIN_JUSTIFICATION_CHARS} characters;
              approvers read it before deciding and it is recorded in the audit trail.{" "}
              <span className="tabular-nums">
                {charCount(values.justification)} / {MAX_JUSTIFICATION_CHARS}
              </span>
            </Hint>
            <FieldError id={`${IDS.justification}-error`} message={shown("justification")} />
          </div>

          <div>
            <label htmlFor={IDS.expiresOn} className="label">
              Expiry date
            </label>
            <input
              id={IDS.expiresOn}
              type="date"
              required
              className="input sm:w-48"
              min={bounds.min}
              max={bounds.max}
              value={values.expiresOn}
              aria-invalid={shown("expiresOn") ? true : undefined}
              aria-describedby={describedBy("expiresOn")}
              onChange={(event) => set("expiresOn", event.target.value)}
              onBlur={() => touch("expiresOn")}
            />
            <Hint id={`${IDS.expiresOn}-hint`}>
              The exception stops applying at 00:00 your time on this date, at most {MAX_EXCEPTION_DAYS} days from now.
              {expiry.ok &&
                ` It would expire in ${formatTimeSpan(expiry.value.getTime() - now)} (${formatDateTime(expiry.value.toISOString())}).`}
            </Hint>
            <FieldError id={`${IDS.expiresOn}-error`} message={shown("expiresOn")} />
          </div>
        </fieldset>

        {serverError && <ErrorState error={serverError} title="The exception was not requested" />}

        <div className="flex flex-wrap items-center gap-2">
          <button type="submit" className="btn-primary" disabled={submitting}>
            {submitting ? "Sending request" : "Send request"}
          </button>
          <button type="button" className="btn-ghost" disabled={submitting} onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}
