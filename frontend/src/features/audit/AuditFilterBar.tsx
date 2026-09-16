import { useId, useRef, useState, type FormEvent } from "react";
import { FilterErrorSummary, FilterTextField } from "../events/FilterFields";
import type { ParamChanges } from "../events/searchParams";
import {
  KNOWN_AUDIT_ACTIONS,
  KNOWN_AUDIT_TARGET_TYPES,
  MAX_ACTION_LENGTH,
  MAX_TARGET_TYPE_LENGTH,
  hasActiveAuditFilters,
  validateAuditFilters,
  type AuditFilterDraft,
  type AuditFilterErrors,
  type AuditFilters,
} from "./auditFilters";

const FIELD_ORDER: readonly (keyof AuditFilterDraft)[] = ["action", "actorId", "targetType"];

export interface AuditFilterBarProps {
  filters: AuditFilters;
  currentUserId: string | null;
  onChange: (changes: ParamChanges) => void;
}

/** Audit filters bound to the address; validated and applied together on submit. */
export function AuditFilterBar({ filters, currentUserId, onChange }: AuditFilterBarProps) {
  const baseId = useId();
  const actionRef = useRef<HTMLInputElement>(null);
  const actorRef = useRef<HTMLInputElement>(null);
  const targetRef = useRef<HTMLInputElement>(null);

  const fromAddress: AuditFilterDraft = {
    action: filters.action ?? "",
    actorId: filters.actorId ?? "",
    targetType: filters.targetType ?? "",
  };
  const basedOn = [fromAddress.action, fromAddress.actorId, fromAddress.targetType].join("\n");
  const [draft, setDraft] = useState<{ basedOn: string; values: AuditFilterDraft } | null>(null);
  const [invalid, setInvalid] = useState<{ basedOn: string; errors: AuditFilterErrors } | null>(null);
  const values = draft?.basedOn === basedOn ? draft.values : fromAddress;
  const errors: AuditFilterErrors = invalid?.basedOn === basedOn ? invalid.errors : {};
  const errorCount = FIELD_ORDER.filter((field) => errors[field]).length;

  function edit(field: keyof AuditFilterDraft, value: string) {
    setDraft({ basedOn, values: { ...values, [field]: value } });
    if (errors[field]) setInvalid({ basedOn, errors: { ...errors, [field]: undefined } });
  }

  function apply(next: AuditFilterDraft) {
    const result = validateAuditFilters(next);
    const firstInvalid = FIELD_ORDER.find((field) => result.errors[field]);
    if (firstInvalid) {
      setDraft({ basedOn, values: next });
      setInvalid({ basedOn, errors: result.errors });
      const target = firstInvalid === "action" ? actionRef : firstInvalid === "actorId" ? actorRef : targetRef;
      target.current?.focus();
      return;
    }
    setDraft(null);
    setInvalid(null);
    onChange({
      action: result.values.action,
      actor_id: result.values.actorId,
      target_type: result.values.targetType,
      offset: null,
    });
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    apply(values);
  }

  const active = hasActiveAuditFilters(filters) || draft?.basedOn === basedOn;

  return (
    <form role="search" aria-label="Filter the audit log" noValidate onSubmit={submit} className="mb-3 flex flex-col gap-3">
      <div className="flex flex-wrap items-start gap-3">
        <FilterTextField
          id={`${baseId}-action`}
          label="Action"
          className="w-full sm:w-60"
          inputRef={actionRef}
          mono
          list={`${baseId}-actions`}
          placeholder="e.g. policy.update"
          maxLength={MAX_ACTION_LENGTH}
          value={values.action}
          error={errors.action}
          onChange={(value) => edit("action", value)}
        />
        <FilterTextField
          id={`${baseId}-actor`}
          label="Actor ID"
          className="w-full sm:w-80"
          inputRef={actorRef}
          mono
          placeholder="User UUID"
          maxLength={64}
          value={values.actorId}
          error={errors.actorId}
          onChange={(value) => edit("actorId", value)}
        />
        <FilterTextField
          id={`${baseId}-target`}
          label="Target type"
          className="w-full sm:w-48"
          inputRef={targetRef}
          mono
          list={`${baseId}-targets`}
          placeholder="e.g. policy"
          maxLength={MAX_TARGET_TYPE_LENGTH}
          value={values.targetType}
          error={errors.targetType}
          onChange={(value) => edit("targetType", value)}
        />
        <datalist id={`${baseId}-actions`}>
          {KNOWN_AUDIT_ACTIONS.map((action) => (
            <option key={action} value={action} />
          ))}
        </datalist>
        <datalist id={`${baseId}-targets`}>
          {KNOWN_AUDIT_TARGET_TYPES.map((type) => (
            <option key={type} value={type} />
          ))}
        </datalist>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button type="submit" className="btn-secondary">
          Apply filters
        </button>
        {currentUserId && filters.actorId !== currentUserId && (
          <button type="button" className="btn-ghost" onClick={() => apply({ ...values, actorId: currentUserId })}>
            Only my actions
          </button>
        )}
        {active && (
          <button
            type="button"
            className="btn-ghost"
            onClick={() => {
              setDraft(null);
              setInvalid(null);
              onChange({ action: null, actor_id: null, target_type: null, offset: null });
            }}
          >
            Clear filters
          </button>
        )}
        <p className="text-xs text-ink-muted">Action and target type match exactly.</p>
      </div>
      <FilterErrorSummary count={errorCount} />
    </form>
  );
}
