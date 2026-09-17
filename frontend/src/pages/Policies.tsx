import { useEffect, useRef, useState, type FormEvent } from "react";
import { toApiError, type ApiError } from "../api/client";
import { activatePolicy, createPolicy, listPolicies, updatePolicy } from "../api/policies";
import { ENVIRONMENTS, type Environment, type Policy, type PolicyWrite } from "../api/types";
import { PERMISSIONS } from "../auth/permissions";
import { usePermission } from "../auth/usePermission";
import { Card } from "../components/Card";
import { CodeBlock } from "../components/CodeBlock";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataTable, type Column } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { SelectField } from "../components/SelectField";
import { useApiQuery } from "../hooks/useApiQuery";
import { formatDateTime, humanize } from "../lib/format";
import { pickOption, stringArray } from "../lib/values";
import { DECISION_FILL } from "../theme/classes";

interface PolicyForm {
  name: string;
  environment: Environment;
  warn_threshold: string;
  block_threshold: string;
  min_package_age_days: string;
  blocked_capabilities: string;
  allowlist: string;
  denylist: string;
}

interface Editor {
  /** null while creating a new policy. */
  policyId: string | null;
  values: PolicyForm;
}

const EMPTY_FORM: PolicyForm = {
  name: "",
  environment: "production",
  warn_threshold: "40",
  block_threshold: "70",
  min_package_age_days: "0",
  blocked_capabilities: "",
  allowlist: "",
  denylist: "",
};

function toForm(policy: Policy): PolicyForm {
  return {
    name: policy.name,
    environment: pickOption(ENVIRONMENTS, policy.environment) ?? "production",
    warn_threshold: String(policy.warn_threshold),
    block_threshold: String(policy.block_threshold),
    min_package_age_days: String(policy.min_package_age_days),
    blocked_capabilities: stringArray(policy.blocked_capabilities).join("\n"),
    allowlist: stringArray(policy.allowlist).join("\n"),
    denylist: stringArray(policy.denylist).join("\n"),
  };
}

function parseList(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/[\n,]/)
        .map((entry) => entry.trim())
        .filter(Boolean),
    ),
  ];
}

function parseWholeNumber(text: string): number | null {
  const trimmed = text.trim();
  return /^\d{1,5}$/.test(trimmed) ? Number(trimmed) : null;
}

/** Mirrors the server's validation so mistakes are reported before the request is sent. */
function validate(form: PolicyForm): { errors: string[]; body: PolicyWrite | null } {
  const errors: string[] = [];
  const name = form.name.trim();
  const warn = parseWholeNumber(form.warn_threshold);
  const block = parseWholeNumber(form.block_threshold);
  const age = parseWholeNumber(form.min_package_age_days);
  if (!name) errors.push("Enter a policy name.");
  if (name.length > 120) errors.push("Policy names can be at most 120 characters.");
  if (warn === null || warn > 100) errors.push("The warn threshold must be a whole number from 0 to 100.");
  if (block === null || block > 100) errors.push("The block threshold must be a whole number from 0 to 100.");
  if (warn !== null && block !== null && warn > block) {
    errors.push("The warn threshold cannot be higher than the block threshold.");
  }
  if (age === null || age > 3650) errors.push("Minimum package age must be a whole number of days from 0 to 3650.");
  if (errors.length > 0 || warn === null || block === null || age === null) return { errors, body: null };
  return {
    errors,
    body: {
      name,
      environment: form.environment,
      warn_threshold: warn,
      block_threshold: block,
      min_package_age_days: age,
      blocked_capabilities: parseList(form.blocked_capabilities),
      allowlist: parseList(form.allowlist),
      denylist: parseList(form.denylist),
    },
  };
}

function ThresholdScale({ warn, block }: { warn: number | null; block: number | null }) {
  if (warn === null || block === null || warn > 100 || block > 100 || warn > block) return null;
  const segments = [
    { decision: "allow" as const, size: warn },
    { decision: "warn" as const, size: block - warn },
    { decision: "block" as const, size: 101 - block },
  ].filter((segment) => segment.size > 0);
  const parts: string[] = [];
  if (warn > 0) parts.push(`below ${warn} are allowed`);
  if (block > warn) parts.push(`${warn} to ${block - 1} warn`);
  parts.push(`${block} and above are blocked`);
  return (
    <div>
      <div aria-hidden="true" className="flex h-2 gap-[2px] overflow-hidden rounded-sm">
        {segments.map((segment) => (
          <span
            key={segment.decision}
            className={DECISION_FILL[segment.decision]}
            style={{ flexGrow: segment.size, flexBasis: 0 }}
          />
        ))}
      </div>
      <p className="mt-1.5 text-xs text-ink-secondary">Risk scores {parts.join(", ")}.</p>
    </div>
  );
}

function NumberField({
  id,
  label,
  value,
  max,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  max: number;
  onChange: (value: string) => void;
}) {
  return (
    <div>
      <label htmlFor={id} className="label">
        {label}
      </label>
      <input
        id={id}
        className="input tabular-nums"
        type="number"
        inputMode="numeric"
        min={0}
        max={max}
        step={1}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  );
}

function ListField({
  id,
  label,
  hint,
  value,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div>
      <label htmlFor={id} className="label">
        {label}
      </label>
      <textarea
        id={id}
        className="input"
        rows={5}
        spellCheck={false}
        aria-describedby={`${id}-hint`}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      <p id={`${id}-hint`} className="mt-1 text-xs text-ink-muted">
        {hint}
      </p>
    </div>
  );
}

export default function Policies() {
  const canWrite = usePermission(PERMISSIONS.POLICY_WRITE);
  const policies = useApiQuery("policies", (signal) => listPolicies({}, { signal }));
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Editor | null>(null);
  const [formErrors, setFormErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [activating, setActivating] = useState<Policy | null>(null);
  const [activateBusy, setActivateBusy] = useState(false);
  const [activateError, setActivateError] = useState<ApiError | null>(null);
  const noticeRef = useRef<HTMLParagraphElement>(null);
  // Bumped after a successful activation. The dialog returns focus to the row's Activate button, which
  // disappears once the reloaded list shows the policy as active, so focus moves to the notice instead.
  // This effect runs after the dialog's own focus restore (unmount effects run first).
  const [noticeFocusRequest, setNoticeFocusRequest] = useState(0);

  useEffect(() => {
    if (noticeFocusRequest > 0) noticeRef.current?.focus();
  }, [noticeFocusRequest]);

  const list = policies.data ?? [];
  const selected =
    list.find((policy) => policy.id === selectedId) ??
    list.find((policy) => policy.is_active && policy.environment === "production") ??
    list.find((policy) => policy.is_active) ??
    list[0] ??
    null;
  const editor: Editor | null =
    draft ??
    (selected
      ? { policyId: selected.id, values: toForm(selected) }
      : canWrite && policies.data
        ? { policyId: null, values: EMPTY_FORM }
        : null);
  const editingPolicy = editor?.policyId ? (list.find((policy) => policy.id === editor.policyId) ?? null) : null;
  const dirty =
    draft !== null &&
    (editingPolicy === null || JSON.stringify(draft.values) !== JSON.stringify(toForm(editingPolicy)));

  function resetMessages() {
    setFormErrors([]);
    setSaveError(null);
    setNotice(null);
  }

  function choose(policy: Policy) {
    setSelectedId(policy.id);
    setDraft(null);
    resetMessages();
  }

  function update<K extends keyof PolicyForm>(field: K, value: PolicyForm[K]) {
    if (!editor) return;
    setDraft({ policyId: editor.policyId, values: { ...editor.values, [field]: value } });
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editor || !canWrite || saving) return;
    const { errors, body } = validate(editor.values);
    setFormErrors(errors);
    setSaveError(null);
    setNotice(null);
    if (!body) return;
    setSaving(true);
    try {
      const saved = editor.policyId ? await updatePolicy(editor.policyId, body) : await createPolicy(body);
      setSelectedId(saved.id);
      setDraft({ policyId: saved.id, values: toForm(saved) });
      setNotice(editor.policyId ? `Saved ${saved.name}.` : `Created ${saved.name}.`);
      policies.reload();
    } catch (err) {
      setSaveError(toApiError(err));
    } finally {
      setSaving(false);
    }
  }

  async function confirmActivate() {
    if (!activating) return;
    setActivateBusy(true);
    setActivateError(null);
    try {
      const activated = await activatePolicy(activating.id);
      const environment = humanize(activated.environment ?? "production").toLowerCase();
      setNotice(`${activated.name} is now the active ${environment} policy.`);
      setActivating(null);
      setNoticeFocusRequest((request) => request + 1);
      policies.reload();
    } catch (err) {
      setActivateError(toApiError(err));
    } finally {
      setActivateBusy(false);
    }
  }

  const columns: Column<Policy>[] = [
    {
      id: "name",
      header: "Name",
      sortValue: (policy) => policy.name,
      cell: (policy) => {
        const current = editor?.policyId === policy.id;
        return (
          <button
            type="button"
            aria-current={current ? "true" : undefined}
            onClick={() => choose(policy)}
            className={`wrap-break-word text-left hover:text-accent hover:underline ${current ? "font-semibold text-ink" : "text-ink"}`}
          >
            {policy.name}
          </button>
        );
      },
    },
    {
      id: "environment",
      header: "Environment",
      sortValue: (policy) => policy.environment ?? "",
      cell: (policy) =>
        policy.environment ? humanize(policy.environment) : <span className="text-ink-muted">Not recorded</span>,
    },
    {
      id: "status",
      header: "Status",
      sortValue: (policy) => policy.is_active,
      cell: (policy) =>
        policy.is_active ? (
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink">
            <span aria-hidden="true" className="h-2 w-2 rounded-full bg-verdict-allow" />
            Active
          </span>
        ) : (
          <span className="text-xs text-ink-muted">Inactive</span>
        ),
    },
    {
      id: "thresholds",
      header: "Warn and block at",
      cell: (policy) => (
        <span className="tabular-nums">
          {policy.warn_threshold} and {policy.block_threshold}
        </span>
      ),
    },
    {
      id: "updated",
      header: "Updated",
      sortValue: (policy) => policy.updated_at ?? policy.created_at,
      cell: (policy) => (
        <span className="whitespace-nowrap text-ink-secondary">{formatDateTime(policy.updated_at ?? policy.created_at)}</span>
      ),
    },
  ];
  if (canWrite) {
    columns.push({
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (policy) =>
        policy.is_active ? null : (
          <button
            type="button"
            className="btn-secondary h-7 px-2"
            onClick={() => {
              setActivateError(null);
              setActivating(policy);
            }}
          >
            Activate
          </button>
        ),
    });
  }

  const activatingEnvironment = humanize(activating?.environment ?? "production").toLowerCase();

  return (
    <>
      <PageHeader
        title="Policies"
        description="A policy turns a scan's risk score and findings into allow, warn or block. Each environment has one active policy."
        actions={
          canWrite ? (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                setDraft({ policyId: null, values: EMPTY_FORM });
                resetMessages();
              }}
            >
              New policy
            </button>
          ) : undefined
        }
      />
      {!canWrite && <p className="mb-4 text-ink-secondary">You can review policies. Changing them requires the admin role.</p>}
      {notice && (
        <p
          ref={noticeRef}
          role="status"
          tabIndex={-1}
          className="mb-4 rounded-r-md border-l-2 border-verdict-allow bg-panel px-4 py-2 text-ink"
        >
          {notice}
        </p>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,5fr)_minmax(0,4fr)]">
        <Card title="All policies" flush>
          <DataTable
            caption="Policies"
            columns={columns}
            rows={policies.data}
            rowKey={(policy) => policy.id}
            loading={policies.loading}
            error={policies.error}
            onRetry={policies.reload}
            empty={
              <EmptyState
                compact
                title="No policies exist yet."
                description={
                  canWrite
                    ? "Create one with New policy. Until then the analysis engine's default thresholds apply."
                    : "Until an administrator creates one, the analysis engine's default thresholds apply."
                }
              />
            }
          />
        </Card>

        {editor ? (
          <Card
            title={editor.policyId ? (canWrite ? "Edit policy" : "Policy settings") : "New policy"}
            description={editingPolicy ? `Version ${editingPolicy.version ?? 1}` : undefined}
          >
            <form onSubmit={(event) => void save(event)} noValidate className="flex flex-col gap-4">
              <fieldset disabled={!canWrite || saving} className="flex min-w-0 flex-col gap-4">
                <legend className="sr-only">Policy settings</legend>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <label htmlFor="policy-name" className="label">
                      Name
                    </label>
                    <input
                      id="policy-name"
                      className="input"
                      maxLength={120}
                      value={editor.values.name}
                      onChange={(event) => update("name", event.target.value)}
                    />
                  </div>
                  <div>
                    <SelectField
                      id="policy-environment"
                      label="Environment"
                      value={editor.values.environment}
                      options={ENVIRONMENTS.map((env) => ({ value: env, label: humanize(env) }))}
                      disabled={!canWrite || saving || Boolean(editingPolicy?.is_active)}
                      onChange={(value) => update("environment", pickOption(ENVIRONMENTS, value) ?? "production")}
                    />
                    {editingPolicy?.is_active && (
                      <p className="mt-1 text-xs text-ink-muted">An active policy cannot move to another environment.</p>
                    )}
                  </div>
                </div>
                <div className="grid gap-4 sm:grid-cols-3">
                  <NumberField
                    id="policy-warn"
                    label="Warn at risk score"
                    value={editor.values.warn_threshold}
                    max={100}
                    onChange={(value) => update("warn_threshold", value)}
                  />
                  <NumberField
                    id="policy-block"
                    label="Block at risk score"
                    value={editor.values.block_threshold}
                    max={100}
                    onChange={(value) => update("block_threshold", value)}
                  />
                  <NumberField
                    id="policy-age"
                    label="Minimum package age (days)"
                    value={editor.values.min_package_age_days}
                    max={3650}
                    onChange={(value) => update("min_package_age_days", value)}
                  />
                </div>
                <ThresholdScale
                  warn={parseWholeNumber(editor.values.warn_threshold)}
                  block={parseWholeNumber(editor.values.block_threshold)}
                />
                <div className="grid gap-4 md:grid-cols-3">
                  <ListField
                    id="policy-capabilities"
                    label="Blocked capabilities"
                    hint="One per line, for example install_hook_exec."
                    value={editor.values.blocked_capabilities}
                    onChange={(value) => update("blocked_capabilities", value)}
                  />
                  <ListField
                    id="policy-allowlist"
                    label="Allowlist"
                    hint="Package names, one per line."
                    value={editor.values.allowlist}
                    onChange={(value) => update("allowlist", value)}
                  />
                  <ListField
                    id="policy-denylist"
                    label="Denylist"
                    hint="Package names to block, one per line."
                    value={editor.values.denylist}
                    onChange={(value) => update("denylist", value)}
                  />
                </div>
              </fieldset>

              {formErrors.length > 0 && (
                <ul role="alert" className="flex flex-col gap-1 rounded-r border-l-2 border-sev-critical bg-sunken px-3 py-2 text-ink">
                  {formErrors.map((message) => (
                    <li key={message}>{message}</li>
                  ))}
                </ul>
              )}
              {saveError && <ErrorState error={saveError} title="The policy was not saved" />}
              {editingPolicy?.document && (
                <CodeBlock label="Policy-as-code document (read-only here)" value={editingPolicy.document} />
              )}
              {canWrite && (
                <div className="flex flex-wrap items-center gap-2">
                  <button type="submit" className="btn-primary" disabled={saving}>
                    {saving ? "Saving" : editor.policyId ? "Save changes" : "Create policy"}
                  </button>
                  {dirty && (
                    <button
                      type="button"
                      className="btn-ghost"
                      disabled={saving}
                      onClick={() => {
                        setDraft(null);
                        resetMessages();
                      }}
                    >
                      Discard changes
                    </button>
                  )}
                </div>
              )}
            </form>
          </Card>
        ) : policies.data ? (
          <EmptyState title="There are no policy settings to show." />
        ) : null}
      </div>

      <ConfirmDialog
        open={activating !== null}
        title={activating ? `Activate ${activating.name}?` : "Activate policy?"}
        description={`It immediately replaces the active ${activatingEnvironment} policy, and new ${activatingEnvironment} scans are evaluated against it.`}
        confirmLabel="Activate policy"
        busy={activateBusy}
        onConfirm={() => void confirmActivate()}
        onCancel={() => {
          if (!activateBusy) setActivating(null);
        }}
      >
        {activateError && <ErrorState error={activateError} title="The policy was not activated" />}
      </ConfirmDialog>
    </>
  );
}
